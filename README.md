# discord-secret-intake

A Hermes plugin that adds a Discord `/secret` slash command. The invoking user types a value into a private modal, and the plugin stores it in your Bitwarden Secrets Manager project via the `bws` CLI. The value never enters the agent's context, the chat, the session transcript, or the plugin's logs. The agent only sees that `NAME` was registered.

## How it works

1. An allowed user runs `/secret name:MY_API_KEY` (optionally `overwrite:true`).
2. A modal visible only to that user asks for the value.
3. The plugin runs `bws secret create` (or `bws secret edit` when `overwrite:true` and the key exists) against the project in `secrets.bitwarden.project_id`.
4. The user gets a private (ephemeral) result. On success the channel gets a value-free notice: `🔐 MY_API_KEY を Bitwarden に登録しました`.
5. Run `hermes secrets bitwarden sync` or restart the gateway to load the new value as an environment variable.

## Requirements

- Hermes `>= 0.21.5` with the Discord platform enabled
- Bitwarden Secrets Manager configured in Hermes (`secrets.bitwarden.enabled`, `project_id`) and `BWS_ACCESS_TOKEN` available to the gateway
- The access token must have **write** access to the project
- The bot must be in each target guild with the `applications.commands` scope

## Configuration

Both settings are required. If either is empty, the command is not registered at all (fail closed).

```yaml
plugins:
  enabled:
    - discord-secret-intake
  entries:
    discord-secret-intake:
      settings:
        guild_ids: ["123456789012345678"]        # servers where /secret is registered
        allowed_user_ids: ["234567890123456789"] # users who may run /secret
```

IDs may be given as a list or a comma-separated string. Invalid entries are dropped.

## Authorization

A user must pass **both** checks:

1. The plugin's own `allowed_user_ids`. This is independent of the gateway's chat policy, so `DISCORD_ALLOW_ALL_USERS=true` does not open secret writes to everyone.
2. The gateway's normal slash-command authorization (channel and role policy).

The command is also registered as guild-only with a default `Manage Server` permission, so most members do not see it. Server admins can change command visibility in Discord, which is why the allowlist above is the real gate.

The command is registered and synced per guild, so the gateway's global command sync does not remove it.

## Key names

`NAME` must match `^[A-Z][A-Z0-9_]{1,63}$`. If a key already exists and `overwrite` is false, nothing is written and the typed value is discarded. If the project contains duplicate keys with the same name, the plugin refuses to change either.

## Security notes and known limits

- **argv exposure:** `bws` 2.0 cannot read a secret value from stdin, so the value is passed as a command-line argument. Another user on the same host may briefly see it in the process list.
- **Not isolated from the agent:** after sync, the value is a normal environment variable of the Hermes process. An agent with terminal access can still read it (for example `echo $NAME`). The plugin keeps values out of chat and transcripts; it is not a sandbox.
- **Discord transport:** modal submissions travel through Discord's servers as interaction payloads.
- **Error messages:** `bws` failures report the return code and the first 200 characters of stderr, with the value masked as `***`. Logs record only the key name, the outcome, and exception type names.
- **Output masking of Bitwarden values:** when the Discord platform connects, the gateway fetches every value in the configured project and registers it with Hermes' exact-value redaction registry (background thread, up to 3 attempts). A successful `/secret` registers its new value at once. Tool output that passes through Hermes' redaction then shows `«redacted-vault-secret»` in place of the value, including bare output such as `echo $NAME`.
  - Limits: exact substring match only. Encoded, transformed, or split forms (base64, URL encoding, a value broken across lines or output chunks) are not masked.
  - Values shorter than 4 characters are not registered, because an exact scrub of a very short value would rewrite unrelated output. Values of 4 or more characters are masked wherever they appear, including inside other words, so a short or common value can rewrite unrelated output.
  - The registry is in memory, per Hermes home, and holds at most 64 entries. Browser-vault and MCP token registrations share that cap, and the oldest entries are evicted first.
  - Values created or changed outside `/secret` (for example with `bws` directly) are masked only after the next gateway start. Output is not masked until the startup sync completes. If every attempt fails, values stay unmasked until restart; the log then shows `secret intake redaction sync gave up`.
  - Only the gateway's Discord connect starts the sync. CLI and cron processes that load the plugin do not fetch values, so their output is not covered.
  - Coverage is limited to output that Hermes passes through `redact_sensitive_text`. The terminal tool calls it with `force=True`. Other tool output paths were not checked one by one.
  - Verified only for in-process plugin loading (the default, `plugins.isolation` unset). This is output masking, not isolation: the agent can still use the value, for example by sending it in a request.
- **Full isolation (optional):** masking only covers output that reaches the model. With the default `local` terminal backend, an agent can still read `.env` or `BWS_ACCESS_TOKEN` from its terminal and send a value out directly. To keep the agent from reaching the values at all, run its tools in a container:

  ```yaml
  terminal:
    backend: docker
    docker_forward_env: []   # forward no host variables into the container
  ```

  In a test with this config (Docker 29, Hermes default sandbox image), the terminal ran inside the container, `~/.hermes`, `.env`, and the `bws` binary were not visible, and none of the Bitwarden-supplied variables or `BWS_ACCESS_TOKEN` were set. File tools (`read_file`, `write_file`) also operated inside the container rather than on the host. Hermes can additionally route the container's outbound traffic through its Docker egress proxy; that part was not tested here.

  Trade-off: the agent can no longer inspect or edit the host Hermes installation, and anything it needs inside the container must be forwarded explicitly. The plugin itself keeps working, because it runs in the gateway process on the host, not in the agent's container.
- The overwrite (`bws secret edit`) path is covered by unit tests only.
- User-facing messages are currently in Japanese.

## Files

- `plugin.yaml` — manifest and `config_schema`
- `__init__.py` — `register(ctx)`; registers the Discord platform handler and reads settings
- `intake.py` — settings, authorization, `bws` client, modal, slash command, guild sync
- `test_intake.py` — unit tests (no network; `bws` is mocked)

## Tests

From the Hermes checkout:

```bash
./venv/bin/python -m pytest /path/to/discord-secret-intake -q
```

## Disable / remove

```bash
hermes plugins disable discord-secret-intake
```

Restart the gateway to apply. Delete the plugin directory to remove it.

## License

MIT. See `LICENSE`.
