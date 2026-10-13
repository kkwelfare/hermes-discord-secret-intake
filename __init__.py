"""discord-secret-intake: Discord /secret modal intake for Bitwarden Secrets Manager.

Registration is cheap. The discord-dependent implementation in intake.py is loaded only
when the Discord adapter calls the platform handler factory.
"""

import importlib.util
import logging
import threading
from pathlib import Path

logger = logging.getLogger("discord_secret_intake")
_PLUGIN_DIR = Path(__file__).resolve().parent
_impl = None
_ctx = None
_redaction_sync_homes: set = set()  # homes whose startup sync already started in this process
_redaction_sync_lock = threading.Lock()


def _load_impl():
    global _impl
    if _impl is None:
        spec = importlib.util.spec_from_file_location(
            "discord_secret_intake_impl", _PLUGIN_DIR / "intake.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError("intake.py could not be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _impl = module
    return _impl


def _settings(impl):
    get = getattr(_ctx, "get_config", None)
    if not callable(get):
        return impl.Settings()
    return impl.Settings(
        guild_ids=get("guild_ids", None),
        allowed_user_ids=get("allowed_user_ids", None),
    )


def _start_redaction_sync(impl):
    """Gateway startup: register the Bitwarden values in the exact-value redaction registry.

    Called from the Discord platform factory, which only the gateway runs at connect(). register()
    also runs in CLI and cron processes, where a bws call would be wasted work. One background
    thread per Hermes home; never raises and never blocks connect().
    """
    home = None
    try:
        from hermes_constants import get_hermes_home
        home = str(get_hermes_home())
        with _redaction_sync_lock:
            if home in _redaction_sync_homes:
                return None
            _redaction_sync_homes.add(home)
        impl.set_redaction_home(home)
        thread = threading.Thread(
            target=impl.sync_vault_redaction, args=(home,),
            name="discord-secret-intake-redaction-sync", daemon=True,
        )
        thread.start()
        return thread
    except Exception as exc:
        if home is not None:
            with _redaction_sync_lock:
                _redaction_sync_homes.discard(home)  # a later connect() may retry
        logger.error("secret intake redaction sync not started error_type=%s", type(exc).__name__)
        return None


def _factory(native, adapter):
    """Platform handler factory, called as factory(native, adapter) at connect()."""
    try:
        impl = _load_impl()
        _start_redaction_sync(impl)
        return impl.install(native, adapter, _settings(impl))
    except Exception as exc:  # the Discord platform must keep connecting
        logger.error("secret intake disabled: error_type=%s", type(exc).__name__)
        return None


def register(ctx):
    global _ctx
    _ctx = ctx
    ctx.register_platform_handler("discord", _factory)
