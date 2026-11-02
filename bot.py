import os
import time
import asyncio
import logging
import sqlite3
from collections import defaultdict, deque
from datetime import timedelta

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN', '').strip()
DB_PATH = os.getenv('DB_PATH', 'security.sqlite3')
DEFAULT_WINDOW = int(os.getenv('ANTINUKE_WINDOW_SECONDS', '12'))
DEFAULT_LOG_CHANNEL_ID = int(os.getenv('LOG_CHANNEL_ID', '0') or 0)

if not TOKEN:
    raise RuntimeError('Missing DISCORD_TOKEN. Copy .env.example to .env and set your bot token.')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
log = logging.getLogger('guardbot')

intents = discord.Intents.default()
intents.guilds = True
intents.members = True  # Enable Server Members Intent in the Developer Portal for join/member events.
intents.moderation = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Conservative defaults: tune these for your server. Actions are counted per executor and event type.
DEFAULT_THRESHOLDS = {
    'channel_delete': 3,
    'role_delete': 2,
    'role_create': 5,
    'ban': 3,
    'kick': 3,
    'webhook_create': 3,
}
WINDOWS = defaultdict(deque)
ALERTED = set()
DB_LOCK = asyncio.Lock()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS settings (
          guild_id INTEGER PRIMARY KEY,
          log_channel_id INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          window_seconds INTEGER NOT NULL DEFAULT 12
        );
        CREATE TABLE IF NOT EXISTS whitelist (
          guild_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          added_by INTEGER NOT NULL,
          added_at INTEGER NOT NULL,
          PRIMARY KEY (guild_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS thresholds (
          guild_id INTEGER NOT NULL,
          action TEXT NOT NULL,
          threshold INTEGER NOT NULL,
          PRIMARY KEY (guild_id, action)
        );
        CREATE TABLE IF NOT EXISTS lockdown_overwrites (
          guild_id INTEGER NOT NULL,
          channel_id INTEGER NOT NULL,
          send_messages INTEGER,
          create_public_threads INTEGER,
          PRIMARY KEY (guild_id, channel_id)
        );
        ''')


def ensure_guild(guild_id: int):
    with db() as conn:
        conn.execute('INSERT OR IGNORE INTO settings(guild_id, log_channel_id, enabled, window_seconds) VALUES(?,?,1,?)',
                     (guild_id, DEFAULT_LOG_CHANNEL_ID, DEFAULT_WINDOW))
        for action, threshold in DEFAULT_THRESHOLDS.items():
            conn.execute('INSERT OR IGNORE INTO thresholds(guild_id, action, threshold) VALUES(?,?,?)',
                         (guild_id, action, threshold))


def get_settings(guild_id: int):
    ensure_guild(guild_id)
    with db() as conn:
        return dict(conn.execute('SELECT * FROM settings WHERE guild_id=?', (guild_id,)).fetchone())


def is_whitelisted(guild_id: int, user_id: int) -> bool:
    with db() as conn:
        return conn.execute('SELECT 1 FROM whitelist WHERE guild_id=? AND user_id=?', (guild_id, user_id)).fetchone() is not None


def get_threshold(guild_id: int, action: str) -> int:
    ensure_guild(guild_id)
    with db() as conn:
        row = conn.execute('SELECT threshold FROM thresholds WHERE guild_id=? AND action=?', (guild_id, action)).fetchone()
        return int(row['threshold']) if row else DEFAULT_THRESHOLDS.get(action, 3)


def get_log_channel(guild: discord.Guild):
    settings = get_settings(guild.id)
    channel_id = int(settings['log_channel_id'] or 0)
    channel = guild.get_channel(channel_id) if channel_id else None
    return channel if isinstance(channel, discord.TextChannel) else None


async def send_log(guild: discord.Guild, title: str, description: str, color=discord.Color.orange()):
    channel = get_log_channel(guild)
    if not channel:
        log.warning('No valid security log channel configured for guild %s', guild.id)
        return
    embed = discord.Embed(title=title[:256], description=description[:4000], color=color, timestamp=discord.utils.utcnow())
    embed.set_footer(text='Security Guard • Audit-log verified where available')
    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        log.exception('Failed to send security log to guild %s', guild.id)


async def find_audit_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int | None = None):
    """Return a recent matching audit entry. Audit log events can arrive slightly after gateway events."""
    for attempt in range(3):
        try:
            async for entry in guild.audit_logs(limit=8, action=action):
                age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                if age > 15:
                    continue
                entry_target_id = getattr(entry.target, 'id', None)
                if target_id is None or entry_target_id == target_id:
                    return entry
        except (discord.Forbidden, discord.HTTPException):
            log.exception('Could not read audit log for guild %s', guild.id)
            return None
        if attempt < 2:
            await asyncio.sleep(0.7)
    return None


async def respond_to_nuke(guild: discord.Guild, actor_id: int, action: str, count: int, threshold: int):
    """Containment is intentionally conservative: strip manageable roles, then timeout if possible; never ban automatically."""
    member = guild.get_member(actor_id)
    if member is None or member.id == guild.owner_id or member.id == bot.user.id:
        await send_log(guild, '🚨 Anti-Nuke triggered',
                       f'Action: `{action}`\nExecutor: <@{actor_id}> (`{actor_id}`)\nThreshold: `{count}/{threshold}`\nAutomatic containment skipped: owner, bot, or member not cached.',
                       discord.Color.red())
        return

    bot_member = guild.me
    details = []
    try:
        if bot_member and bot_member.guild_permissions.manage_roles and member.top_role < bot_member.top_role:
            removable = [r for r in member.roles if r != guild.default_role and not r.managed and r < bot_member.top_role]
            if removable:
                await member.remove_roles(*removable, reason=f'Anti-Nuke containment: {action} threshold exceeded')
                details.append(f'Removed {len(removable)} manageable role(s)')
    except (discord.Forbidden, discord.HTTPException) as exc:
        details.append(f'Role removal failed ({type(exc).__name__})')

    try:
        if bot_member and bot_member.guild_permissions.moderate_members and member.top_role < bot_member.top_role:
            await member.timeout(timedelta(minutes=10), reason=f'Anti-Nuke containment: {action} threshold exceeded')
            details.append('Timed out for 10 minutes')
    except (discord.Forbidden, discord.HTTPException) as exc:
        details.append(f'Timeout failed ({type(exc).__name__})')

    if not details:
        details.append('Could not contain automatically; check bot permissions and role hierarchy')
    await send_log(guild, '🚨 Anti-Nuke containment triggered',
                   f'Action: `{action}`\nExecutor: <@{actor_id}> (`{actor_id}`)\nRate: `{count}/{threshold}` in configured window\nResponse: ' + '; '.join(details),
                   discord.Color.red())


async def record_action(guild: discord.Guild, actor: discord.abc.User, action: str, target: str = 'unknown'):
    settings = get_settings(guild.id)
    if not settings['enabled']:
        return
    if actor.id == (bot.user.id if bot.user else 0):
        return
    if is_whitelisted(guild.id, actor.id):
        await send_log(guild, 'ℹ️ Whitelisted action', f'Action: `{action}`\nExecutor: {actor.mention} (`{actor.id}`)\nTarget: `{target}`')
        return

    now = time.monotonic()
    window = max(5, min(60, int(settings['window_seconds'])))
    key = (guild.id, actor.id, action)
    bucket = WINDOWS[key]
    bucket.append(now)
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    count = len(bucket)
    threshold = get_threshold(guild.id, action)

    await send_log(guild, '⚠️ Security event',
                   f'Action: `{action}`\nExecutor: {actor.mention} (`{actor.id}`)\nTarget: `{target}`\nRate: `{count}/{threshold}` in {window}s',
                   discord.Color.red() if count >= threshold else discord.Color.orange())

    alert_key = (guild.id, actor.id, action)
    if count >= threshold and alert_key not in ALERTED:
        ALERTED.add(alert_key)
        await respond_to_nuke(guild, actor.id, action, count, threshold)


@bot.event
async def on_ready():
    init_db()
    try:
        synced = await bot.tree.sync()
        log.info('Synced %s global slash commands', len(synced))
    except discord.HTTPException:
        log.exception('Slash command sync failed')
    log.info('Logged in as %s (ID %s)', bot.user, bot.user.id if bot.user else '?')
    for guild in bot.guilds:
        ensure_guild(guild.id)


@bot.event
async def on_guild_join(guild: discord.Guild):
    ensure_guild(guild.id)


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    entry = await find_audit_actor(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
    if entry and entry.user:
        await record_action(channel.guild, entry.user, 'channel_delete', f'{channel.name} ({channel.id})')
    else:
        await send_log(channel.guild, '⚠️ Channel deleted; executor unknown', f'Channel: `{channel.name}` (`{channel.id}`)\nCould not match a recent Audit Log entry. Verify bot has View Audit Log.', discord.Color.red())


@bot.event
async def on_guild_role_delete(role: discord.Role):
    entry = await find_audit_actor(role.guild, discord.AuditLogAction.role_delete, role.id)
    if entry and entry.user:
        await record_action(role.guild, entry.user, 'role_delete', f'{role.name} ({role.id})')
    else:
        await send_log(role.guild, '⚠️ Role deleted; executor unknown', f'Role: `{role.name}` (`{role.id}`)\nCould not match a recent Audit Log entry.', discord.Color.red())


@bot.event
async def on_guild_role_create(role: discord.Role):
    entry = await find_audit_actor(role.guild, discord.AuditLogAction.role_create, role.id)
    if entry and entry.user:
        await record_action(role.guild, entry.user, 'role_create', f'{role.name} ({role.id})')


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User | discord.Member):
    entry = await find_audit_actor(guild, discord.AuditLogAction.ban, user.id)
    if entry and entry.user:
        await record_action(guild, entry.user, 'ban', f'{user} ({user.id})')


@bot.event
async def on_member_remove(member: discord.Member):
    # Member-remove fires for leaves and kicks. Only count it when Audit Log confirms a kick.
    entry = await find_audit_actor(member.guild, discord.AuditLogAction.kick, member.id)
    if entry and entry.user:
        await record_action(member.guild, entry.user, 'kick', f'{member} ({member.id})')


@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    entry = await find_audit_actor(channel.guild, discord.AuditLogAction.webhook_create)
    if entry and entry.user and getattr(entry.target, 'channel_id', channel.id) == channel.id:
        await record_action(channel.guild, entry.user, 'webhook_create', f'channel {channel.name} ({channel.id})')


@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    if before.permissions != after.permissions:
        entry = await find_audit_actor(after.guild, discord.AuditLogAction.role_update, after.id)
        if entry and entry.user:
            changed = [name for name, value in after.permissions if value and not getattr(before.permissions, name, False)]
            if changed:
                await send_log(after.guild, '🔐 Role permissions changed',
                               f'Role: {after.mention} (`{after.id}`)\nExecutor: {entry.user.mention} (`{entry.user.id}`)\nNewly enabled permissions: `{", ".join(changed[:30])}`',
                               discord.Color.red())


# ---------- Slash commands ----------
def admin_only():
    return app_commands.checks.has_permissions(manage_guild=True)


@bot.tree.command(name='security', description='Show Security Guard status and configuration')
@app_commands.guild_only()
@admin_only()
async def security(interaction: discord.Interaction):
    settings = get_settings(interaction.guild_id)
    with db() as conn:
        wl_count = conn.execute('SELECT COUNT(*) AS n FROM whitelist WHERE guild_id=?', (interaction.guild_id,)).fetchone()['n']
    embed = discord.Embed(title='🛡️ Security Guard Status', color=discord.Color.green() if settings['enabled'] else discord.Color.red())
    embed.add_field(name='Anti-Nuke', value='Enabled' if settings['enabled'] else 'Disabled', inline=True)
    embed.add_field(name='Window', value=f"{settings['window_seconds']} seconds", inline=True)
    embed.add_field(name='Whitelist entries', value=str(wl_count), inline=True)
    channel = interaction.guild.get_channel(int(settings['log_channel_id'] or 0))
    embed.add_field(name='Log channel', value=channel.mention if channel else 'Not configured', inline=False)
    embed.add_field(name='Default thresholds', value='\n'.join(f'`{k}`: {get_threshold(interaction.guild_id, k)}' for k in DEFAULT_THRESHOLDS), inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name='security_enable', description='Enable or disable Anti-Nuke monitoring')
@app_commands.guild_only()
@admin_only()
@app_commands.describe(enabled='True to enable, False to disable')
async def security_enable(interaction: discord.Interaction, enabled: bool):
    ensure_guild(interaction.guild_id)
    with db() as conn:
        conn.execute('UPDATE settings SET enabled=? WHERE guild_id=?', (int(enabled), interaction.guild_id))
    await interaction.response.send_message(f'Anti-Nuke monitoring is now **{"enabled" if enabled else "disabled"}**.', ephemeral=True)
    await send_log(interaction.guild, '⚙️ Security configuration changed', f'Changed by {interaction.user.mention}: Anti-Nuke **{"enabled" if enabled else "disabled"}**')


@bot.tree.command(name='set_logs', description='Set the channel used for security logs')
@app_commands.guild_only()
@admin_only()
@app_commands.describe(channel='Private text channel for security alerts')
async def set_logs(interaction: discord.Interaction, channel: discord.TextChannel):
    ensure_guild(interaction.guild_id)
    if not channel.permissions_for(interaction.guild.me).send_messages or not channel.permissions_for(interaction.guild.me).embed_links:
        await interaction.response.send_message('I need Send Messages and Embed Links in that channel.', ephemeral=True)
        return
    with db() as conn:
        conn.execute('UPDATE settings SET log_channel_id=? WHERE guild_id=?', (channel.id, interaction.guild_id))
    await interaction.response.send_message(f'Security logs will be sent to {channel.mention}.', ephemeral=True)
    await send_log(interaction.guild, '✅ Security logs configured', f'Configured by {interaction.user.mention}.')


@bot.tree.command(name='whitelist_add', description='Add a trusted member to the Anti-Nuke whitelist')
@app_commands.guild_only()
@admin_only()
@app_commands.describe(member='Member trusted to perform sensitive actions')
async def whitelist_add(interaction: discord.Interaction, member: discord.Member):
    if member.id == interaction.guild.owner_id:
        await interaction.response.send_message('The server owner is already exempt from automatic containment.', ephemeral=True)
        return
    with db() as conn:
        conn.execute('INSERT OR REPLACE INTO whitelist(guild_id,user_id,added_by,added_at) VALUES(?,?,?,?)',
                     (interaction.guild_id, member.id, interaction.user.id, int(time.time())))
    await interaction.response.send_message(f'Added {member.mention} to the whitelist.', ephemeral=True)
    await send_log(interaction.guild, '🟢 Whitelist updated', f'{member.mention} added by {interaction.user.mention}.')


@bot.tree.command(name='whitelist_remove', description='Remove a member from the Anti-Nuke whitelist')
@app_commands.guild_only()
@admin_only()
async def whitelist_remove(interaction: discord.Interaction, member: discord.Member):
    with db() as conn:
        cur = conn.execute('DELETE FROM whitelist WHERE guild_id=? AND user_id=?', (interaction.guild_id, member.id))
    await interaction.response.send_message('Removed from whitelist.' if cur.rowcount else 'That member was not whitelisted.', ephemeral=True)
    await send_log(interaction.guild, '🟠 Whitelist updated', f'{member.mention} removed by {interaction.user.mention}.')


@bot.tree.command(name='whitelist_list', description='List trusted members')
@app_commands.guild_only()
@admin_only()
async def whitelist_list(interaction: discord.Interaction):
    with db() as conn:
        rows = conn.execute('SELECT user_id,added_by,added_at FROM whitelist WHERE guild_id=? ORDER BY added_at DESC LIMIT 50', (interaction.guild_id,)).fetchall()
    if not rows:
        text = 'Whitelist is empty.'
    else:
        text = '\n'.join(f'• <@{r["user_id"]}> (`{r["user_id"]}`) — added by <@{r["added_by"]}>' for r in rows)
    await interaction.response.send_message(text[:1900], ephemeral=True)


@bot.tree.command(name='set_threshold', description='Set Anti-Nuke event threshold')
@app_commands.guild_only()
@admin_only()
@app_commands.choices(action=[app_commands.Choice(name=k, value=k) for k in DEFAULT_THRESHOLDS])
@app_commands.describe(action='Event category', count='Actions within the configured window (1-20)')
async def set_threshold(interaction: discord.Interaction, action: app_commands.Choice[str], count: app_commands.Range[int, 1, 20]):
    with db() as conn:
        conn.execute('INSERT OR REPLACE INTO thresholds(guild_id,action,threshold) VALUES(?,?,?)', (interaction.guild_id, action.value, count))
    await interaction.response.send_message(f'Threshold for `{action.value}` set to **{count}**.', ephemeral=True)
    await send_log(interaction.guild, '⚙️ Threshold changed', f'{interaction.user.mention} set `{action.value}` threshold to `{count}`.')


@bot.tree.command(name='set_window', description='Set Anti-Nuke detection window in seconds')
@app_commands.guild_only()
@admin_only()
@app_commands.describe(seconds='Detection window, 5-60 seconds')
async def set_window(interaction: discord.Interaction, seconds: app_commands.Range[int, 5, 60]):
    with db() as conn:
        conn.execute('UPDATE settings SET window_seconds=? WHERE guild_id=?', (seconds, interaction.guild_id))
    await interaction.response.send_message(f'Anti-Nuke detection window set to **{seconds} seconds**.', ephemeral=True)


@bot.tree.command(name='lockdown', description='Temporarily deny @everyone sending messages in text channels')
@app_commands.guild_only()
@admin_only()
@app_commands.describe(enabled='True to enable lockdown, False to restore saved message permissions')
async def lockdown(interaction: discord.Interaction, enabled: bool):
    guild = interaction.guild
    everyone = guild.default_role
    await interaction.response.defer(ephemeral=True, thinking=True)
    changed = 0
    if enabled:
        for channel in guild.text_channels:
            if channel.id in [r['channel_id'] for r in db().execute('SELECT channel_id FROM lockdown_overwrites WHERE guild_id=?', (guild.id,)).fetchall()]:
                continue
            overwrite = channel.overwrites_for(everyone)
            old_send = None if overwrite.send_messages is None else int(overwrite.send_messages)
            old_threads = None if overwrite.create_public_threads is None else int(overwrite.create_public_threads)
            with db() as conn:
                conn.execute('INSERT OR IGNORE INTO lockdown_overwrites VALUES(?,?,?,?)', (guild.id, channel.id, old_send, old_threads))
            overwrite.send_messages = False
            overwrite.create_public_threads = False
            try:
                await channel.set_permissions(everyone, overwrite=overwrite, reason=f'Emergency lockdown requested by {interaction.user}')
                changed += 1
            except (discord.Forbidden, discord.HTTPException):
                pass
    else:
        with db() as conn:
            rows = conn.execute('SELECT channel_id,send_messages,create_public_threads FROM lockdown_overwrites WHERE guild_id=?', (guild.id,)).fetchall()
        for row in rows:
            channel = guild.get_channel(row['channel_id'])
            if not isinstance(channel, discord.TextChannel):
                continue
            overwrite = channel.overwrites_for(everyone)
            overwrite.send_messages = None if row['send_messages'] is None else bool(row['send_messages'])
            overwrite.create_public_threads = None if row['create_public_threads'] is None else bool(row['create_public_threads'])
            try:
                await channel.set_permissions(everyone, overwrite=overwrite, reason=f'Lockdown restore requested by {interaction.user}')
                changed += 1
            except (discord.Forbidden, discord.HTTPException):
                pass
        with db() as conn:
            conn.execute('DELETE FROM lockdown_overwrites WHERE guild_id=?', (guild.id,))
    state = 'enabled' if enabled else 'disabled/restored'
    await interaction.followup.send(f'Lockdown {state}. Updated {changed} text channel(s). Some channels may be skipped due to permissions.', ephemeral=True)
    await send_log(guild, '🚧 Emergency lockdown', f'Lockdown {state} by {interaction.user.mention}. Updated {changed} text channel(s).', discord.Color.red() if enabled else discord.Color.green())


@bot.tree.command(name='security_test', description='Send a test alert to the configured security log channel')
@app_commands.guild_only()
@admin_only()
async def security_test(interaction: discord.Interaction):
    channel = get_log_channel(interaction.guild)
    if not channel:
        await interaction.response.send_message('Set a log channel first with `/set_logs`.', ephemeral=True)
        return
    await interaction.response.send_message(f'Test alert sent to {channel.mention}.', ephemeral=True)
    await send_log(interaction.guild, '🧪 Security test alert', f'Test requested by {interaction.user.mention}. If you can see this, log delivery works.', discord.Color.green())


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        message = 'You need the **Manage Server** permission to use this command.'
    else:
        log.exception('Slash command error', exc_info=error)
        message = 'Command failed. Check the bot logs and permissions.'
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


if __name__ == '__main__':
    init_db()
    bot.run(TOKEN, log_handler=None)
