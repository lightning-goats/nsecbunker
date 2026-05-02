import importlib.util
from datetime import datetime, timezone
from pathlib import Path


def _load_models_module():
    models_path = Path(__file__).resolve().parents[1] / "models.py"
    spec = importlib.util.spec_from_file_location("nsecbunker_models_under_test", models_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_bunker_key_dict_keeps_database_secret_fields():
    models = _load_models_module()

    key = models.BunkerKey(
        id="key-1",
        wallet="wallet-1",
        pubkey_hex="pubkey-1",
        encrypted_nsec="encrypted",
        created_at=datetime.now(timezone.utc),
    )

    payload = key.dict()

    assert payload["encrypted_nsec"] == "encrypted"
    assert "stored" not in payload


def test_public_bunker_key_strips_secret_and_reports_storage_state():
    models = _load_models_module()

    key = models.BunkerKey(
        id="key-1",
        wallet="wallet-1",
        pubkey_hex="pubkey-1",
        encrypted_nsec="encrypted",
        created_at=datetime.now(timezone.utc),
    )

    payload = models.PublicBunkerKey.from_bunker_key(key).dict()

    assert payload["stored"] is True
    assert "encrypted_nsec" not in payload
