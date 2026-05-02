import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace


def _load_services_module():
    package_name = "nsecbunker_testpkg"
    module_name = f"{package_name}.services"
    services_path = Path(__file__).resolve().parents[1] / "services.py"

    package = types.ModuleType(package_name)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[package_name] = package

    logger = SimpleNamespace(info=lambda *a, **k: None)
    loguru = types.ModuleType("loguru")
    loguru.logger = logger
    sys.modules["loguru"] = loguru

    class DummyEvent:
        def __init__(self, *, kind, tags, content, pubkey):
            self.kind = kind
            self.tags = tags
            self.content = content
            self.pubkey = pubkey
            self.signed_with = None

        def sign(self, private_key_hex):
            self.signed_with = private_key_hex

        def to_dict(self):
            return {
                "kind": self.kind,
                "tags": self.tags,
                "content": self.content,
                "pubkey": self.pubkey,
                "sig": "dummy-sig",
                "id": "dummy-event-id",
            }

    pynostr = types.ModuleType("pynostr")
    pynostr_event = types.ModuleType("pynostr.event")
    pynostr_event.Event = DummyEvent
    pynostr.event = pynostr_event  # type: ignore[attr-defined]
    sys.modules["pynostr"] = pynostr
    sys.modules["pynostr.event"] = pynostr_event

    crud = types.ModuleType(f"{package_name}.crud")

    async def get_keys(wallet_id):
        return [
            SimpleNamespace(id="key-a", wallet=wallet_id, pubkey_hex="pubkey-a"),
            SimpleNamespace(id="key-b", wallet=wallet_id, pubkey_hex="pubkey-b"),
        ]

    async def get_key(key_id):
        mapping = {
            "key-a": SimpleNamespace(id="key-a", wallet="wallet-1", pubkey_hex="pubkey-a"),
            "key-b": SimpleNamespace(id="key-b", wallet="wallet-1", pubkey_hex="pubkey-b"),
        }
        return mapping.get(key_id)

    async def get_permission_for_signing(wallet_id, extension_id, kind):
        return SimpleNamespace(
            key_id="key-b",
            extension_id=extension_id,
            kind=kind,
            rate_limit_count=None,
            rate_limit_seconds=None,
        )

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                key_id="key-a",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=None,
                rate_limit_seconds=None,
            ),
            SimpleNamespace(
                key_id="key-b",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=None,
                rate_limit_seconds=None,
            ),
        ]

    async def get_decrypted_private_key(key_id):
        return f"secret-for-{key_id}"

    async def create_signing_log(key_id, extension_id, kind, event_id):
        create_signing_log.calls.append((key_id, extension_id, kind, event_id))

    create_signing_log.calls = []

    async def count_recent_signings(key_id, extension_id, kind, seconds):
        return 0

    crud.count_recent_signings = count_recent_signings
    crud.create_signing_log = create_signing_log
    crud.get_decrypted_private_key = get_decrypted_private_key
    crud.get_key = get_key
    crud.get_keys = get_keys
    crud.get_permissions = get_permissions
    crud.get_permission_for_signing = get_permission_for_signing
    sys.modules[f"{package_name}.crud"] = crud

    spec = importlib.util.spec_from_file_location(module_name, services_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module, create_signing_log


def test_sign_event_uses_requested_key_when_that_key_has_permission():
    services, create_signing_log = _load_services_module()

    signed = asyncio.run(
        services.sign_event(
            wallet_id="wallet-1",
            extension_id="cyberherd_messaging",
            unsigned_event={"kind": 1, "tags": [], "content": "hello"},
            key_id="key-a",
        )
    )

    assert signed["pubkey"] == "pubkey-a"
    assert create_signing_log.calls == [
        ("key-a", "cyberherd_messaging", 1, "dummy-event-id")
    ]


def test_sign_event_serializes_rate_limited_signing_for_same_permission():
    services, _ = _load_services_module()
    active_checks = 0
    max_active_checks = 0

    async def get_permissions(wallet_id):
        return [
            SimpleNamespace(
                key_id="key-a",
                extension_id="cyberherd_messaging",
                kind=1,
                rate_limit_count=10,
                rate_limit_seconds=60,
            )
        ]

    async def count_recent_signings(key_id, extension_id, kind, seconds):
        nonlocal active_checks, max_active_checks
        active_checks += 1
        max_active_checks = max(max_active_checks, active_checks)
        await asyncio.sleep(0.01)
        active_checks -= 1
        return 0

    async def run_two_signings():
        await asyncio.gather(
            services.sign_event(
                wallet_id="wallet-1",
                extension_id="cyberherd_messaging",
                unsigned_event={"kind": 1, "tags": [], "content": "first"},
                key_id="key-a",
            ),
            services.sign_event(
                wallet_id="wallet-1",
                extension_id="cyberherd_messaging",
                unsigned_event={"kind": 1, "tags": [], "content": "second"},
                key_id="key-a",
            ),
        )

    services.get_permissions = get_permissions
    services.count_recent_signings = count_recent_signings

    asyncio.run(run_two_signings())

    assert max_active_checks == 1
