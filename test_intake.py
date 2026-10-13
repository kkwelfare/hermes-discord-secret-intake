"""Unit tests for discord-secret-intake. No network: bws subprocess calls are mocked."""

import asyncio
import importlib.util
import json
import re
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_DIR = Path(__file__).resolve().parent
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))

import discord  # noqa: E402
import intake  # noqa: E402

GUILD_ID = 900000000000000001
USER_ID = 900000000000000002
OTHER_USER_ID = 900000000000000003
SETTINGS = intake.Settings(guild_ids=[GUILD_ID], allowed_user_ids=[USER_ID])
BIN = "/fake/bws"
PROJECT = "11111111-2222-3333-4444-555555555555"
TOKEN = "DUMMY-BWS-TOKEN-FOR-TESTS"
VALUE = 'pa"ss-VALUE-123'
VALUE_ESC = json.dumps(VALUE)[1:-1]


def _proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _load_plugin(sync=False):
    spec = importlib.util.spec_from_file_location(
        "discord_secret_intake_plugin_under_test", PLUGIN_DIR / "__init__.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not sync:
        # Unit tests must not start the background Bitwarden fetch (no real bws calls).
        module._start_redaction_sync = lambda impl: None
    return module


def _interaction(user_id=USER_ID):
    inter = mock.MagicMock(name="interaction")
    inter.user.id = user_id
    inter.response.send_message = mock.AsyncMock()
    inter.response.send_modal = mock.AsyncMock()
    inter.response.defer = mock.AsyncMock()
    inter.followup.send = mock.AsyncMock()
    inter.channel.send = mock.AsyncMock()
    return inter


def _outbound_text(inter):
    texts = []
    for m in (inter.response.send_message, inter.response.defer, inter.followup.send, inter.channel.send):
        for c in m.call_args_list:
            texts.append(repr(c.args) + repr(c.kwargs))
    return "\n".join(texts)


class NameValidationTests(unittest.TestCase):
    def test_accepts_valid_names(self):
        for name in ["AB", "MY_KEY", "A1_B2", "A" + "B" * 63]:
            with self.subTest(name=name):
                self.assertTrue(intake.valid_name(name))

    def test_rejects_invalid_names(self):
        for name in ["A", "my_key", "1ABC", "A-B", "A B", "A" + "B" * 64, "", "ABC\n", "ABC;rm", None]:
            with self.subTest(name=name):
                self.assertFalse(intake.valid_name(name))


class BwsClientTests(unittest.TestCase):
    def setUp(self):
        self.client = intake.BwsClient(BIN, PROJECT)

    def test_store_creates_when_key_is_new(self):
        with mock.patch.dict(os.environ, {"BWS_ACCESS_TOKEN": TOKEN}), \
                mock.patch("intake.subprocess.run") as run:
            run.side_effect = [
                _proc(stdout="[]"),
                _proc(stdout=json.dumps({"id": "new-id", "key": "MY_KEY"})),
            ]
            result = self.client.store("MY_KEY", VALUE, overwrite=False)
        self.assertEqual(result, "created")
        argvs = [c.args[0] for c in run.call_args_list]
        self.assertEqual(argvs[0], [BIN, "secret", "list", PROJECT, "-o", "json"])
        self.assertEqual(argvs[1], [BIN, "secret", "create", "-o", "json", "--", "MY_KEY", VALUE, PROJECT])
        self.assertEqual(len(argvs), 2)
        for c in run.call_args_list:
            self.assertEqual(c.kwargs["env"]["BWS_ACCESS_TOKEN"], TOKEN)
            self.assertEqual(c.kwargs["timeout"], 30)
            self.assertTrue(c.kwargs["capture_output"])
            self.assertTrue(c.kwargs["text"])

    def test_store_edits_when_overwrite_true(self):
        with mock.patch("intake.subprocess.run") as run:
            run.side_effect = [
                _proc(stdout=json.dumps([{"id": "sid-1", "key": "MY_KEY"}])),
                _proc(stdout="{}"),
            ]
            result = self.client.store("MY_KEY", VALUE, overwrite=True)
        self.assertEqual(result, "updated")
        argvs = [c.args[0] for c in run.call_args_list]
        self.assertEqual(argvs[1], [BIN, "secret", "edit", "-o", "json", f"--value={VALUE}", "sid-1"])
        self.assertEqual(len(argvs), 2)

    def test_store_returns_exists_without_writing(self):
        with mock.patch("intake.subprocess.run") as run:
            run.return_value = _proc(stdout=json.dumps([{"id": "sid-1", "key": "MY_KEY", "value": "old"}]))
            result = self.client.store("MY_KEY", VALUE, overwrite=False)
        self.assertEqual(result, "exists")
        self.assertEqual(run.call_count, 1)

    def test_store_refuses_ambiguous_duplicate_keys(self):
        duplicate = json.dumps([{"id": "a", "key": "MY_KEY"}, {"id": "b", "key": "MY_KEY"}])
        with mock.patch("intake.subprocess.run") as run:
            run.return_value = _proc(stdout=duplicate)
            with self.assertRaises(intake.BwsError):
                self.client.store("MY_KEY", VALUE, overwrite=True)
        self.assertEqual(run.call_count, 1)

    def test_failure_message_never_contains_value(self):
        stderr = f"error: failed for {VALUE} and {VALUE_ESC}\n"
        with mock.patch("intake.subprocess.run", return_value=_proc(returncode=1, stderr=stderr)):
            with self.assertRaises(intake.BwsError) as cm:
                self.client.store("MY_KEY", VALUE, overwrite=False)
        msg = str(cm.exception)
        self.assertNotIn(VALUE, msg)
        self.assertNotIn(VALUE_ESC, msg)
        self.assertIn("***", msg)
        self.assertIn("returncode=1", msg)

    def test_timeout_message_hides_argv(self):
        timeout = subprocess.TimeoutExpired(
            cmd=[BIN, "secret", "create", "--", "MY_KEY", VALUE, PROJECT], timeout=30
        )
        with mock.patch("intake.subprocess.run", side_effect=[_proc(stdout="[]"), timeout]):
            with self.assertRaises(intake.BwsError) as cm:
                self.client.store("MY_KEY", VALUE, overwrite=False)
        self.assertNotIn(VALUE, str(cm.exception))
        self.assertTrue(cm.exception.__suppress_context__)

    def test_store_rejects_bad_name_before_any_subprocess(self):
        with mock.patch("intake.subprocess.run") as run:
            with self.assertRaises(intake.BwsError):
                self.client.store("bad-name", VALUE, overwrite=False)
        run.assert_not_called()


class SlashCommandTests(unittest.TestCase):
    def _command(self, verdict):
        adapter = mock.MagicMock(name="adapter")
        adapter._evaluate_slash_authorization.return_value = verdict
        return intake._build_command(adapter, SETTINGS)

    def test_metadata_is_guild_safe_secret_command(self):
        cmd = self._command((True, None))
        self.assertEqual(cmd.name, "secret")
        types = {p.name: p.type for p in cmd.parameters}
        self.assertEqual(types["name"], discord.AppCommandOptionType.string)
        self.assertEqual(types["overwrite"], discord.AppCommandOptionType.boolean)

    def test_command_is_guild_only_and_hidden_by_default(self):
        cmd = self._command((True, None))
        self.assertTrue(cmd.guild_only)
        self.assertTrue(cmd.default_permissions.manage_guild)

    def test_user_outside_plugin_allowlist_is_refused_even_if_gateway_allows_all(self):
        cmd = self._command((True, None))  # gateway says yes (DISCORD_ALLOW_ALL_USERS)
        inter = _interaction(user_id=OTHER_USER_ID)
        with mock.patch("intake._resolve_client") as resolve:
            asyncio.run(cmd.callback(inter, name="MY_KEY", overwrite=True))
        inter.response.send_modal.assert_not_called()
        resolve.assert_not_called()
        self.assertIs(inter.response.send_message.call_args.kwargs.get("ephemeral"), True)

    def test_missing_user_is_refused(self):
        cmd = self._command((True, None))
        inter = _interaction()
        inter.user = None
        asyncio.run(cmd.callback(inter, name="MY_KEY", overwrite=False))
        inter.response.send_modal.assert_not_called()

    def test_denied_user_gets_refusal_and_no_modal(self):
        cmd = self._command((False, "user not in allowlist"))
        inter = _interaction()
        asyncio.run(cmd.callback(inter, name="MY_KEY", overwrite=False))
        inter.response.send_modal.assert_not_called()
        inter.response.send_message.assert_awaited_once()
        self.assertIs(inter.response.send_message.call_args.kwargs.get("ephemeral"), True)

    def test_invalid_name_gets_error_and_no_modal(self):
        cmd = self._command((True, None))
        inter = _interaction()
        asyncio.run(cmd.callback(inter, name="bad-name", overwrite=False))
        inter.response.send_modal.assert_not_called()
        self.assertIs(inter.response.send_message.call_args.kwargs.get("ephemeral"), True)

    def test_allowed_valid_name_opens_modal(self):
        cmd = self._command((True, None))
        inter = _interaction()
        with mock.patch("intake._resolve_client", return_value=intake.BwsClient(BIN, PROJECT)):
            asyncio.run(cmd.callback(inter, name="MY_KEY", overwrite=True))
        inter.response.send_modal.assert_awaited_once()
        self.assertIsInstance(inter.response.send_modal.call_args.args[0], intake.SecretModal)
        inter.response.send_message.assert_not_called()


class ModalSubmitTests(unittest.TestCase):
    def _submit(self, side_effect, overwrite=False):
        inter = _interaction()
        client = intake.BwsClient(BIN, PROJECT)

        async def scenario():
            modal = intake.SecretModal(client, "MY_KEY", overwrite)
            with mock.patch.object(discord.ui.TextInput, "value", new_callable=mock.PropertyMock,
                                   return_value=VALUE), \
                    mock.patch.dict(os.environ, {"BWS_ACCESS_TOKEN": TOKEN}), \
                    mock.patch("intake.subprocess.run", side_effect=side_effect) as run:
                with self.assertLogs("discord_secret_intake", level="DEBUG") as logs:
                    await modal.on_submit(inter)
            return run, logs

        run, logs = asyncio.run(scenario())
        return inter, run, "\n".join(logs.output)

    def test_success_leaks_no_value_to_channel_or_logs(self):
        inter, run, logs_text = self._submit([
            _proc(stdout="[]"),
            _proc(stdout=json.dumps({"id": "n1", "key": "MY_KEY", "value": VALUE})),
        ])
        inter.response.defer.assert_awaited_once()
        self.assertIs(inter.response.defer.call_args.kwargs.get("ephemeral"), True)
        followup = inter.followup.send.call_args
        self.assertIn("保存しました", followup.args[0])
        self.assertIs(followup.kwargs.get("ephemeral"), True)
        inter.channel.send.assert_awaited_once()
        channel_text = inter.channel.send.call_args.args[0]
        self.assertIn("MY_KEY", channel_text)
        self.assertNotIn(VALUE, channel_text)
        self.assertNotIn(VALUE, _outbound_text(inter))
        self.assertNotIn(VALUE, logs_text)
        self.assertNotIn(VALUE_ESC, logs_text)

    def test_failure_reports_scrubbed_error_only(self):
        stderr = f"boom {VALUE} {VALUE_ESC}"
        inter, _run, logs_text = self._submit([_proc(returncode=1, stderr=stderr)])
        text = inter.followup.send.call_args.args[0]
        self.assertIn("保存に失敗しました", text)
        self.assertIn("***", text)
        self.assertNotIn(VALUE, text)
        self.assertNotIn(VALUE, _outbound_text(inter))
        self.assertNotIn(VALUE, logs_text)
        inter.channel.send.assert_not_called()

    def test_exists_writes_nothing_and_says_so(self):
        inter, run, logs_text = self._submit([
            _proc(stdout=json.dumps([{"id": "sid-1", "key": "MY_KEY"}])),
        ], overwrite=False)
        self.assertEqual(run.call_count, 1)
        text = inter.followup.send.call_args.args[0]
        self.assertIn("既に存在", text)
        inter.channel.send.assert_not_called()
        self.assertNotIn(VALUE, logs_text)

    def test_on_error_logs_type_only(self):
        inter = _interaction()
        client = intake.BwsClient(BIN, PROJECT)

        async def scenario():
            modal = intake.SecretModal(client, "MY_KEY", False)
            with self.assertLogs("discord_secret_intake", level="ERROR") as logs:
                await modal.on_error(inter, RuntimeError(VALUE))
            return logs

        logs = asyncio.run(scenario())
        logs_text = "\n".join(logs.output)
        self.assertIn("RuntimeError", logs_text)
        self.assertNotIn(VALUE, logs_text)
        self.assertNotIn(VALUE, _outbound_text(inter))


class SettingsTests(unittest.TestCase):
    def test_parse_ids_accepts_lists_and_csv_and_drops_junk(self):
        s = intake.Settings(guild_ids="1, 2,abc,-3,0", allowed_user_ids=[5, "6", True, None, "x"])
        self.assertEqual(s.guild_ids, frozenset({1, 2}))
        self.assertEqual(s.allowed_user_ids, frozenset({5, 6}))

    def test_empty_settings_report_problems(self):
        self.assertEqual(intake.Settings().problems(), ["guild_ids", "allowed_user_ids"])


def _ctx(settings):
    ctx = mock.MagicMock()
    ctx.get_config.side_effect = lambda key, default=None: settings.get(key, default)
    return ctx


class InstallTests(unittest.TestCase):
    def test_registers_guild_command_and_schedules_guild_sync(self):
        plugin = _load_plugin()
        plugin.register(_ctx({"guild_ids": [GUILD_ID], "allowed_user_ids": [USER_ID]}))
        bot = mock.MagicMock(name="bot")
        bot.tree.sync = mock.AsyncMock(return_value=[])
        adapter = mock.MagicMock(name="adapter")

        async def scenario():
            tasks = plugin._factory(bot, adapter)
            self.assertTrue(tasks)
            await asyncio.gather(*tasks)

        asyncio.run(scenario())
        args, kwargs = bot.tree.add_command.call_args
        self.assertEqual(args[0].name, "secret")
        self.assertEqual(kwargs["guild"].id, GUILD_ID)
        bot.tree.sync.assert_awaited_once()
        self.assertEqual(bot.tree.sync.call_args.kwargs["guild"].id, GUILD_ID)

    def test_not_installed_without_allowed_users(self):
        for settings in ({"guild_ids": [GUILD_ID]}, {"allowed_user_ids": [USER_ID]}, {}):
            with self.subTest(settings=settings):
                plugin = _load_plugin()
                plugin.register(_ctx(settings))
                bot = mock.MagicMock(name="bot")
                with self.assertLogs("discord_secret_intake", level="WARNING"):
                    self.assertIsNone(plugin._factory(bot, mock.MagicMock()))
                bot.tree.add_command.assert_not_called()

    def test_register_declares_discord_platform_handler(self):
        plugin = _load_plugin()
        ctx = mock.MagicMock()
        plugin.register(ctx)
        ctx.register_platform_handler.assert_called_once_with("discord", plugin._factory)

    def test_bot_without_tree_is_skipped(self):
        plugin = _load_plugin()
        plugin.register(_ctx({"guild_ids": [GUILD_ID], "allowed_user_ids": [USER_ID]}))
        self.assertIsNone(plugin._factory(object(), mock.MagicMock()))

    def test_module_has_no_print_calls(self):
        source = (PLUGIN_DIR / "intake.py").read_text(encoding="utf-8")
        self.assertNotIn("print(", source)

    def test_no_deployment_specific_ids_in_source(self):
        for name in ("intake.py", "__init__.py", "plugin.yaml"):
            source = (PLUGIN_DIR / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\\d{17,20}", source), name)


FIXTURE_A = "Lantern-Quill-4481-Harbor"
FIXTURE_B = "Cobalt-Saddle-7730-Meadow"
FIXTURE_SHORT = "abc"


class RedactionRegistrationTests(unittest.TestCase):
    """Values reach the agent.redact registry and output is scrubbed; uses a temporary home."""

    def setUp(self):
        import tempfile
        from hermes_constants import set_hermes_home_override
        self._tmp = tempfile.TemporaryDirectory()
        self._token = set_hermes_home_override(self._tmp.name)
        intake.set_redaction_home(None)

    def tearDown(self):
        from agent.redact import clear_vault_redaction_values
        from hermes_constants import reset_hermes_home_override
        clear_vault_redaction_values()
        intake.set_redaction_home(None)
        reset_hermes_home_override(self._token)
        self._tmp.cleanup()

    def _redact(self, text):
        from agent.redact import redact_sensitive_text
        return redact_sensitive_text(text, force=True)

    def test_fixture_evades_generic_redaction(self):
        # Before registration the bare fixture passes through, so the masking tests exercise the registry.
        self.assertEqual(self._redact(f"value: {FIXTURE_A}"), f"value: {FIXTURE_A}")

    def test_bare_and_key_value_forms_are_masked_after_registration(self):
        intake.register_redaction_values([FIXTURE_A, FIXTURE_B])
        for value in (FIXTURE_A, FIXTURE_B):
            for text in (value, f"echo {value}", f"MY_KEY={value}", f"[{value}]"):
                with self.subTest(text=text):
                    self.assertNotIn(value, self._redact(text))

    def test_short_and_empty_values_are_skipped(self):
        registered, skipped = intake.register_redaction_values([FIXTURE_SHORT, "", FIXTURE_A])
        self.assertEqual((registered, skipped), (1, 2))
        self.assertEqual(self._redact(f"x {FIXTURE_SHORT} y"), f"x {FIXTURE_SHORT} y")

    def test_startup_sync_registers_every_project_value_and_logs_counts_only(self):
        listing = json.dumps([
            {"id": "1", "key": "ALPHA_KEY", "value": FIXTURE_A},
            {"id": "2", "key": "BETA_KEY", "value": FIXTURE_B},
            {"id": "3", "key": "EMPTY_KEY", "value": ""},
            {"id": "4", "key": "NO_VALUE"},
        ])
        client = intake.BwsClient(BIN, PROJECT)
        with mock.patch("intake._resolve_client", return_value=client), \
                mock.patch("intake.subprocess.run", return_value=_proc(stdout=listing)) as run, \
                self.assertLogs("discord_secret_intake", level="INFO") as logs:
            intake.sync_vault_redaction(self._tmp.name)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], [BIN, "secret", "list", PROJECT, "-o", "json"])
        self.assertNotIn(FIXTURE_A, self._redact(f"ALPHA_KEY={FIXTURE_A}"))
        self.assertNotIn(FIXTURE_B, self._redact(FIXTURE_B))
        logs_text = "\n".join(logs.output)
        self.assertIn("registered=2 skipped=0", logs_text)
        self.assertNotIn(FIXTURE_A, logs_text)
        self.assertNotIn(FIXTURE_B, logs_text)

    def test_startup_sync_failure_retries_then_logs_error_type_only(self):
        failure = _proc(returncode=1, stderr=f"boom {FIXTURE_A}")
        with mock.patch("intake._resolve_client", return_value=intake.BwsClient(BIN, PROJECT)), \
                mock.patch("intake.subprocess.run", return_value=failure) as run, \
                mock.patch.object(intake, "REDACTION_RETRY_SECONDS", 0), \
                self.assertLogs("discord_secret_intake", level="WARNING") as logs:
            intake.sync_vault_redaction(self._tmp.name)  # must not raise
        self.assertEqual(run.call_count, intake.REDACTION_ATTEMPTS)
        logs_text = "\n".join(logs.output)
        self.assertIn("error_type=BwsError", logs_text)
        self.assertIn("gave up", logs_text)
        self.assertNotIn(FIXTURE_A, logs_text)

    def test_successful_secret_create_registers_new_value(self):
        inter = _interaction()
        client = intake.BwsClient(BIN, PROJECT)
        intake.set_redaction_home(self._tmp.name)

        async def scenario():
            modal = intake.SecretModal(client, "MY_KEY", False)
            with mock.patch.object(discord.ui.TextInput, "value", new_callable=mock.PropertyMock,
                                   return_value=FIXTURE_A), \
                    mock.patch.dict(os.environ, {"BWS_ACCESS_TOKEN": TOKEN}), \
                    mock.patch("intake.subprocess.run", side_effect=[
                        _proc(stdout="[]"),
                        _proc(stdout=json.dumps({"id": "n1", "key": "MY_KEY"})),
                    ]):
                await modal.on_submit(inter)

        asyncio.run(scenario())
        self.assertIn("保存しました", inter.followup.send.call_args.args[0])
        self.assertNotIn(FIXTURE_A, self._redact(f"MY_KEY={FIXTURE_A}"))
        self.assertNotIn(FIXTURE_A, self._redact(FIXTURE_A))

    def test_exists_result_registers_nothing(self):
        inter = _interaction()
        client = intake.BwsClient(BIN, PROJECT)

        async def scenario():
            modal = intake.SecretModal(client, "MY_KEY", False)
            with mock.patch.object(discord.ui.TextInput, "value", new_callable=mock.PropertyMock,
                                   return_value=FIXTURE_B), \
                    mock.patch.dict(os.environ, {"BWS_ACCESS_TOKEN": TOKEN}), \
                    mock.patch("intake.subprocess.run", side_effect=[
                        _proc(stdout=json.dumps([{"id": "sid-1", "key": "MY_KEY"}])),
                    ]):
                await modal.on_submit(inter)

        asyncio.run(scenario())
        self.assertIn("既に存在", inter.followup.send.call_args.args[0])
        self.assertEqual(self._redact(FIXTURE_B), FIXTURE_B)


class StartupTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from hermes_constants import set_hermes_home_override
        self._tmp = tempfile.TemporaryDirectory()
        self._token = set_hermes_home_override(self._tmp.name)

    def tearDown(self):
        from hermes_constants import reset_hermes_home_override
        reset_hermes_home_override(self._token)
        self._tmp.cleanup()

    def test_background_sync_starts_once_per_home(self):
        from hermes_constants import get_hermes_home
        plugin = _load_plugin(sync=True)
        impl = mock.MagicMock(name="impl")
        with mock.patch("threading.Thread") as thread_cls:
            first = plugin._start_redaction_sync(impl)
            second = plugin._start_redaction_sync(impl)
        self.assertEqual(thread_cls.call_count, 1)
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        home = str(get_hermes_home())
        impl.set_redaction_home.assert_called_once_with(home)
        kwargs = thread_cls.call_args.kwargs
        self.assertIs(kwargs["target"], impl.sync_vault_redaction)
        self.assertEqual(kwargs["args"], (home,))
        self.assertTrue(kwargs["daemon"])

    def test_thread_start_failure_is_contained_and_retryable(self):
        plugin = _load_plugin(sync=True)
        impl = mock.MagicMock(name="impl")
        with mock.patch("threading.Thread", side_effect=RuntimeError("no threads")):
            self.assertIsNone(plugin._start_redaction_sync(impl))
        # A failed start must not block a later connect() from retrying.
        with mock.patch("threading.Thread") as thread_cls:
            self.assertIsNotNone(plugin._start_redaction_sync(impl))
        self.assertEqual(thread_cls.call_count, 1)

    def test_secret_command_still_installs_when_sync_start_fails(self):
        plugin = _load_plugin(sync=True)
        plugin.register(_ctx({"guild_ids": [GUILD_ID], "allowed_user_ids": [USER_ID]}))
        bot = mock.MagicMock(name="bot")
        bot.tree.sync = mock.AsyncMock(return_value=[])

        async def scenario():
            with mock.patch("threading.Thread", side_effect=RuntimeError("no threads")):
                tasks = plugin._factory(bot, mock.MagicMock(name="adapter"))
            self.assertTrue(tasks)
            await asyncio.gather(*tasks)

        asyncio.run(scenario())
        self.assertEqual(bot.tree.add_command.call_args.args[0].name, "secret")


if __name__ == "__main__":
    unittest.main()
