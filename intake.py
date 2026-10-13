"""Discord /secret modal intake for Bitwarden Secrets Manager.

The value is typed into a Discord modal that only the invoking user sees, then handed to
bws as an argv element. It is never echoed to chat, never written to logs, and never put
into exception messages. README.md lists the argv exposure limit.

Do not add ``from __future__ import annotations`` here: discord.py reads the slash command
parameter annotations from the callback's real objects.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Optional

import discord
from discord import app_commands

logger = logging.getLogger("discord_secret_intake")

NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
BWS_TIMEOUT_SECONDS = 30
STDERR_LIMIT = 200
MAX_VALUE_LENGTH = 4000
MASK = "***"
ACTION_LABEL = {"created": "新規作成", "updated": "上書き更新"}
_SYNC_TASKS: set = set()  # strong refs: the loop keeps only weak refs to tasks
# Exact-value redaction (agent.redact registry). Shorter values are not registered: an exact
# substring scrub of a 1-3 character value would rewrite unrelated output.
REDACTION_MIN_LENGTH = 4
REDACTION_ATTEMPTS = 3
REDACTION_RETRY_SECONDS = 10
_REDACTION_HOME: Optional[str] = None  # gateway Hermes home that owns the registry entries


class BwsError(Exception):
    """A bws failure. The message never contains the secret value."""


def _parse_ids(raw: Any) -> frozenset:
    """Normalize a settings value (list or comma-separated string) to a set of int snowflakes.

    Anything that is not a positive integer is dropped, so a malformed setting narrows access
    instead of widening it.
    """
    if raw is None:
        return frozenset()
    if isinstance(raw, (str, int)) and not isinstance(raw, bool):
        items = str(raw).split(",")
    elif isinstance(raw, (list, tuple, set, frozenset)):
        items = list(raw)
    else:
        return frozenset()
    out = set()
    for item in items:
        if isinstance(item, bool):
            continue
        text = str(item).strip()
        if text.isdigit() and int(text) > 0:
            out.add(int(text))
    return frozenset(out)


class Settings:
    """Plugin settings. Empty allowlists mean the command is not installed (fail closed)."""

    def __init__(self, guild_ids: Any = None, allowed_user_ids: Any = None) -> None:
        self.guild_ids = _parse_ids(guild_ids)
        self.allowed_user_ids = _parse_ids(allowed_user_ids)

    def problems(self) -> list:
        missing = []
        if not self.guild_ids:
            missing.append("guild_ids")
        if not self.allowed_user_ids:
            missing.append("allowed_user_ids")
        return missing


def plugin_user_allowed(interaction: Any, settings: Settings) -> bool:
    user = getattr(interaction, "user", None)
    user_id = getattr(user, "id", None)
    try:
        return user_id is not None and int(user_id) in settings.allowed_user_ids
    except (TypeError, ValueError):
        return False


def valid_name(name: Any) -> bool:
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None


def _scrub(text: str, value: str) -> str:
    """Mask the secret value, both raw and JSON-escaped, in bws output."""
    if not text:
        return ""
    out = text
    if value:
        for needle in {value, json.dumps(value)[1:-1]}:
            out = out.replace(needle, MASK)
    return out


def _parse_id(stdout: str) -> Optional[str]:
    try:
        data = json.loads(stdout)
    except (TypeError, ValueError):
        return None
    if isinstance(data, dict) and data.get("id"):
        return str(data["id"])
    return None


class BwsClient:
    """Thin wrapper over the bws CLI. Values travel only in argv and are never logged."""

    def __init__(self, binary: Any, project_id: str, server_url: str = "") -> None:
        self._binary = str(binary)
        self._project_id = project_id
        self._server_url = server_url

    def _run(self, args: list, *, scrub: str = "") -> str:
        env = os.environ.copy()  # BWS_ACCESS_TOKEN passes through unchanged
        if self._server_url:
            env["BWS_SERVER_URL"] = self._server_url
        try:
            proc = subprocess.run(
                [self._binary, *args],
                env=env,
                capture_output=True,
                text=True,
                timeout=BWS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            # TimeoutExpired.__str__ embeds the argv, which can contain the value.
            raise BwsError(f"bws がタイムアウトしました（{BWS_TIMEOUT_SECONDS}秒）") from None
        except (OSError, ValueError) as exc:
            raise BwsError(f"bws を実行できませんでした: {type(exc).__name__}") from None
        if proc.returncode != 0:
            stderr = _scrub(proc.stderr or "", scrub)[:STDERR_LIMIT]
            raise BwsError(
                f"bws が失敗しました（returncode={proc.returncode}）: {stderr or '(stderr なし)'}"
            )
        return proc.stdout or ""

    def find_id(self, name: str, *, scrub: str = "") -> Optional[str]:
        out = self._run(["secret", "list", self._project_id, "-o", "json"], scrub=scrub)
        try:
            items = json.loads(out.strip() or "[]")
        except ValueError:
            raise BwsError("bws の一覧出力を解析できませんでした") from None
        if not isinstance(items, list):
            raise BwsError("bws の一覧出力の形式が想定外です")
        ids = [
            str(item["id"])
            for item in items
            if isinstance(item, dict) and item.get("key") == name and item.get("id")
        ]
        if len(ids) > 1:
            raise BwsError(f"同名の secret が {len(ids)} 件あるため変更しませんでした")
        return ids[0] if ids else None

    def list_values(self) -> list:
        """Return (key, value) pairs for every secret in the project that has a value.

        The pairs go only to the redaction registry; callers must not log or return them.
        """
        out = self._run(["secret", "list", self._project_id, "-o", "json"])
        try:
            items = json.loads(out.strip() or "[]")
        except ValueError:
            raise BwsError("bws の一覧出力を解析できませんでした") from None
        if not isinstance(items, list):
            raise BwsError("bws の一覧出力の形式が想定外です")
        pairs = []
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("value"), str) and item["value"]:
                pairs.append((str(item.get("key") or ""), item["value"]))
        return pairs

    def create(self, name: str, value: str) -> Optional[str]:
        # "--" ends option parsing, so a value that starts with "-" stays positional.
        out = self._run(
            ["secret", "create", "-o", "json", "--", name, value, self._project_id],
            scrub=value,
        )
        return _parse_id(out)

    def edit_value(self, secret_id: str, value: str) -> None:
        self._run(["secret", "edit", "-o", "json", f"--value={value}", secret_id], scrub=value)

    def delete(self, secret_id: str) -> None:
        self._run(["secret", "delete", "-o", "json", secret_id])

    def store(self, name: str, value: str, overwrite: bool) -> str:
        """Return "created", "updated", or "exists" (exists means nothing was written)."""
        if not valid_name(name):
            raise BwsError("NAME が不正です")
        if not value or len(value) > MAX_VALUE_LENGTH:
            raise BwsError("値の長さが範囲外です")
        existing = self.find_id(name, scrub=value)
        if existing is None:
            self.create(name, value)
            return "created"
        if not overwrite:
            return "exists"
        self.edit_value(existing, value)
        return "updated"


def set_redaction_home(home: Optional[str]) -> None:
    """Record the gateway's Hermes home so registry writes use the same scope as tool output."""
    global _REDACTION_HOME
    _REDACTION_HOME = home


def register_redaction_values(values: Any, home: Optional[str] = None) -> tuple:
    """Register exact secret values with agent.redact. Returns (registered, skipped) counts.

    Values are never logged or returned. Empty and too-short values are skipped.
    """
    from agent.redact import register_vault_redaction_value
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    token = set_hermes_home_override(home) if home else None
    registered = skipped = 0
    try:
        for value in values:
            if isinstance(value, str) and len(value) >= REDACTION_MIN_LENGTH:
                register_vault_redaction_value(value)
                registered += 1
            else:
                skipped += 1
    finally:
        if token is not None:
            reset_hermes_home_override(token)
    return registered, skipped


def sync_vault_redaction(home: str) -> None:
    """Run the startup sync with ``home`` as the Hermes home, so config and registry agree."""
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    token = set_hermes_home_override(home)
    try:
        _sync_vault_redaction_body(home)
    finally:
        reset_hermes_home_override(token)


def _sync_vault_redaction_body(home: str) -> None:
    """Background startup sync: register every value in the configured Bitwarden project.

    Runs in a daemon thread and retries on failure. Logs the outcome and exception type only;
    never raises.
    """
    for attempt in range(1, REDACTION_ATTEMPTS + 1):
        try:
            pairs = _resolve_client().list_values()
            registered, skipped = register_redaction_values([value for _key, value in pairs], home)
            logger.info("secret intake redaction registered=%d skipped=%d", registered, skipped)
            return
        except Exception as exc:
            logger.warning("secret intake redaction sync attempt=%d error_type=%s",
                           attempt, type(exc).__name__)
        if attempt < REDACTION_ATTEMPTS:
            time.sleep(REDACTION_RETRY_SECONDS)
    logger.error("secret intake redaction sync gave up attempts=%d", REDACTION_ATTEMPTS)


class SecretModal(discord.ui.Modal):
    def __init__(self, client: BwsClient, name: str, overwrite: bool) -> None:
        super().__init__(title=f"Bitwarden: {name}"[:45], timeout=300)
        self._client = client
        self._name = name
        self._overwrite = overwrite
        self.value_input = discord.ui.TextInput(
            label="値（Bitwarden にのみ保存されます）",
            style=discord.TextStyle.short,
            required=True,
            max_length=MAX_VALUE_LENGTH,
        )
        self.add_item(self.value_input)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        # Discord requires an acknowledgement within 3 seconds; bws can take longer.
        await interaction.response.defer(ephemeral=True, thinking=True)
        value = self.value_input.value
        if not value or not value.strip():
            await interaction.followup.send("❌ 値が空のため保存しませんでした。", ephemeral=True)
            return
        try:
            action = await asyncio.to_thread(self._client.store, self._name, value, self._overwrite)
        except Exception as exc:
            logger.warning("secret intake failed name=%s error_type=%s", self._name, type(exc).__name__)
            detail = str(exc) if isinstance(exc, BwsError) else "内部エラー"
            await interaction.followup.send(f"❌ 保存に失敗しました: {detail}", ephemeral=True)
            return
        if action == "exists":
            logger.info("secret intake not written (exists) name=%s", self._name)
            await interaction.followup.send(
                f"⚠️ {self._name} は既に存在するため保存しませんでした。"
                "上書きするには overwrite:true で /secret を実行し直してください。",
                ephemeral=True,
            )
            return
        logger.info("secret intake stored name=%s action=%s", self._name, action)
        try:
            # Register before the reply goes out, so the scrub covers the new value from here on.
            register_redaction_values([value], _REDACTION_HOME)
        except Exception as exc:
            logger.warning("secret intake redaction register failed error_type=%s", type(exc).__name__)
        await interaction.followup.send(
            f"✅ {self._name} を Bitwarden に保存しました（{ACTION_LABEL.get(action, action)}）。\n"
            "反映: `hermes secrets bitwarden sync` を実行するか gateway を再起動してください。",
            ephemeral=True,
        )
        channel = interaction.channel
        if channel is not None:
            try:
                await channel.send(f"🔐 {self._name} を Bitwarden に登録しました")
            except Exception as exc:
                logger.warning("secret intake notice failed name=%s error_type=%s", self._name, type(exc).__name__)

    async def on_error(self, interaction: discord.Interaction, error: Exception) -> None:
        # Log the exception type only: the message may contain the submitted value.
        logger.error("secret intake modal error_type=%s", type(error).__name__)
        try:
            await interaction.followup.send("❌ 内部エラーのため保存できませんでした。", ephemeral=True)
        except Exception as exc:
            logger.error("secret intake error reply failed error_type=%s", type(exc).__name__)


def _configured_bitwarden() -> tuple[str, str]:
    from hermes_cli.config import load_config_readonly

    cfg = load_config_readonly() or {}
    secrets_cfg = cfg.get("secrets") if isinstance(cfg, dict) else None
    block = (secrets_cfg or {}).get("bitwarden") if isinstance(secrets_cfg, dict) else None
    block = block if isinstance(block, dict) else {}
    return str(block.get("project_id") or "").strip(), str(block.get("server_url") or "").strip()


def _resolve_client() -> BwsClient:
    from agent.secret_sources.bitwarden import find_bws

    binary = find_bws()
    if binary is None:
        raise BwsError("bws バイナリが見つかりません")
    project_id, server_url = _configured_bitwarden()
    if not project_id:
        raise BwsError("secrets.bitwarden.project_id が未設定です")
    return BwsClient(binary, project_id, server_url=server_url)


async def _handle_secret(
    interaction: discord.Interaction, adapter: Any, settings: Settings, name: str, overwrite: bool,
) -> None:
    # Gate 1: the plugin's own allowlist. Independent of the gateway's DISCORD_ALLOW_ALL_USERS,
    # so a permissive chat policy never opens secret writes.
    if not plugin_user_allowed(interaction, settings):
        logger.info("secret intake denied reason=not-in-plugin-allowlist")
        await interaction.response.send_message("⛔ このコマンドは使えません。", ephemeral=True)
        return
    # Gate 2: the gateway's own slash authorization (channel/role policy) still applies.
    try:
        allowed, reason = adapter._evaluate_slash_authorization(interaction)
    except Exception as exc:
        logger.error("secret intake auth check failed error_type=%s", type(exc).__name__)
        allowed, reason = False, "auth-check-error"
    if not allowed:
        logger.info("secret intake denied reason=%s", reason)
        await interaction.response.send_message("⛔ このコマンドは使えません。", ephemeral=True)
        return
    if not valid_name(name):
        await interaction.response.send_message(
            "❌ NAME は英大文字で始まり、英大文字・数字・アンダースコアのみ（2〜64字）で指定してください。",
            ephemeral=True,
        )
        return
    try:
        client = _resolve_client()
    except BwsError as exc:
        await interaction.response.send_message(f"❌ {exc}", ephemeral=True)
        return
    except Exception as exc:
        logger.error("secret intake setup failed error_type=%s", type(exc).__name__)
        await interaction.response.send_message("❌ Bitwarden の設定を読めませんでした。ログを確認してください。", ephemeral=True)
        return
    await interaction.response.send_modal(SecretModal(client, name, bool(overwrite)))


def _build_command(adapter: Any, settings: Settings) -> app_commands.Command:
    @app_commands.describe(
        name="Bitwarden に登録するキー名（例: MY_API_KEY）",
        overwrite="同名のキーがある場合に値を上書きする",
    )
    async def secret(interaction: discord.Interaction, name: str, overwrite: bool = False) -> None:
        await _handle_secret(interaction, adapter, settings, name, overwrite)

    cmd = app_commands.Command(
        name="secret",
        description="Bitwarden Secrets Manager に値を登録（モーダルで入力）",
        callback=secret,
    )
    # Hidden from members without Manage Server by default; the plugin allowlist is still the
    # real gate (server admins can override command visibility).
    cmd.default_permissions = discord.Permissions(manage_guild=True)
    cmd.guild_only = True
    return cmd


def _log_sync_done(task: "asyncio.Task") -> None:
    if task.cancelled():
        logger.warning("secret intake guild sync cancelled")
        return
    exc = task.exception()
    if exc is not None:
        logger.error("secret intake guild sync failed error_type=%s", type(exc).__name__)
    else:
        logger.info("secret intake guild sync done")


def install(bot: Any, adapter: Any, settings: Optional[Settings] = None) -> Optional[list]:
    """Register /secret as a guild command in each configured guild and schedule guild-only syncs.

    Returns the scheduled sync tasks, or None when nothing was installed. With no configured
    guilds or no allowed users the command is not registered at all (fail closed).
    """
    settings = settings or Settings()
    missing = settings.problems()
    if missing:
        logger.warning("secret intake not installed: missing settings %s", ",".join(missing))
        return None
    tree = getattr(bot, "tree", None)
    if tree is None:
        logger.warning("secret intake skipped: bot has no command tree")
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    tasks = []
    for guild_id in sorted(settings.guild_ids):
        guild = discord.Object(id=guild_id)
        try:
            tree.add_command(_build_command(adapter, settings), guild=guild)
        except Exception as exc:
            logger.error("secret intake command registration failed guild=%s error_type=%s",
                         guild_id, type(exc).__name__)
            continue
        if loop is None:
            logger.warning("secret intake: no running loop; guild sync not scheduled")
            continue
        task = loop.create_task(tree.sync(guild=guild))
        _SYNC_TASKS.add(task)
        task.add_done_callback(_SYNC_TASKS.discard)
        task.add_done_callback(_log_sync_done)
        tasks.append(task)
    return tasks or None
