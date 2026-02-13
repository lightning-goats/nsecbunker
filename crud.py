from datetime import datetime, timezone

from lnbits.db import Database
from lnbits.helpers import (
    decrypt_internal_message,
    encrypt_internal_message,
    urlsafe_short_hash,
)

from .helpers import parse_nostr_private_key
from .models import (
    BunkerKey,
    BunkerPermission,
    CreateKeyData,
    CreatePermissionData,
    SigningLog,
    UpdatePermissionData,
)

db = Database("ext_nsecbunker")


# --- Keys ---


async def create_key(wallet_id: str, data: CreateKeyData) -> BunkerKey:
    private_key = parse_nostr_private_key(data.private_key)
    private_key_hex = private_key.hex()
    pubkey_hex = private_key.public_key.hex()
    encrypted_nsec = encrypt_internal_message(private_key_hex)

    key = BunkerKey(
        id=urlsafe_short_hash(),
        wallet=wallet_id,
        pubkey_hex=pubkey_hex,
        encrypted_nsec=encrypted_nsec or "",
        created_at=datetime.now(timezone.utc),
    )
    await db.insert("nsecbunker.keys", key)
    return key


async def get_keys(wallet_id: str) -> list[BunkerKey]:
    return await db.fetchall(
        "SELECT * FROM nsecbunker.keys WHERE wallet = :wallet "
        "ORDER BY created_at DESC",
        {"wallet": wallet_id},
        BunkerKey,
    )


async def get_key(key_id: str) -> BunkerKey | None:
    return await db.fetchone(
        "SELECT * FROM nsecbunker.keys WHERE id = :id",
        {"id": key_id},
        BunkerKey,
    )


async def delete_key(key_id: str) -> None:
    await db.execute(
        "DELETE FROM nsecbunker.keys WHERE id = :id",
        {"id": key_id},
    )


async def get_decrypted_private_key(key_id: str) -> str:
    key = await get_key(key_id)
    if not key:
        raise LookupError(f"Key {key_id} not found")
    decrypted = decrypt_internal_message(key.encrypted_nsec)
    if not decrypted:
        raise RuntimeError(f"Failed to decrypt key {key_id}")
    # strip PKCS7 padding bytes left by AES decryption
    return "".join(c for c in decrypted if c >= " ")


# --- Permissions ---


async def create_permission(
    wallet_id: str, data: CreatePermissionData
) -> BunkerPermission:
    perm = BunkerPermission(
        id=urlsafe_short_hash(),
        wallet=wallet_id,
        extension_id=data.extension_id,
        key_id=data.key_id,
        kind=data.kind,
        rate_limit_count=data.rate_limit_count,
        rate_limit_seconds=data.rate_limit_seconds,
        created_at=datetime.now(timezone.utc),
    )
    await db.insert("nsecbunker.permissions", perm)
    return perm


async def get_permissions(wallet_id: str) -> list[BunkerPermission]:
    return await db.fetchall(
        "SELECT * FROM nsecbunker.permissions WHERE wallet = :wallet "
        "ORDER BY created_at DESC",
        {"wallet": wallet_id},
        BunkerPermission,
    )


async def get_permission(perm_id: str) -> BunkerPermission | None:
    return await db.fetchone(
        "SELECT * FROM nsecbunker.permissions WHERE id = :id",
        {"id": perm_id},
        BunkerPermission,
    )


async def get_permission_for_signing(
    wallet_id: str, extension_id: str, kind: int
) -> BunkerPermission | None:
    return await db.fetchone(
        "SELECT * FROM nsecbunker.permissions "
        "WHERE wallet = :wallet AND extension_id = :extension_id "
        "AND kind = :kind",
        {"wallet": wallet_id, "extension_id": extension_id, "kind": kind},
        BunkerPermission,
    )


async def update_permission(
    perm_id: str, data: UpdatePermissionData
) -> BunkerPermission:
    perm = await get_permission(perm_id)
    if not perm:
        raise LookupError(f"Permission {perm_id} not found")
    await db.execute(
        "UPDATE nsecbunker.permissions "
        "SET rate_limit_count = :rate_limit_count, "
        "rate_limit_seconds = :rate_limit_seconds "
        "WHERE id = :id",
        {
            "id": perm_id,
            "rate_limit_count": data.rate_limit_count,
            "rate_limit_seconds": data.rate_limit_seconds,
        },
    )
    updated = await get_permission(perm_id)
    assert updated is not None
    return updated


async def delete_permission(perm_id: str) -> None:
    await db.execute(
        "DELETE FROM nsecbunker.permissions WHERE id = :id",
        {"id": perm_id},
    )


async def delete_permissions_for_key(key_id: str) -> None:
    await db.execute(
        "DELETE FROM nsecbunker.permissions WHERE key_id = :key_id",
        {"key_id": key_id},
    )


# --- Signing Log ---


async def create_signing_log(
    key_id: str, extension_id: str, kind: int, event_id: str
) -> SigningLog:
    log = SigningLog(
        id=urlsafe_short_hash(),
        key_id=key_id,
        extension_id=extension_id,
        kind=kind,
        event_id=event_id,
        created_at=datetime.now(timezone.utc),
    )
    await db.insert("nsecbunker.signing_log", log)
    return log


async def get_signing_logs(wallet_id: str, limit: int = 50) -> list[SigningLog]:
    return await db.fetchall(
        "SELECT sl.* FROM nsecbunker.signing_log sl "
        "JOIN nsecbunker.keys k ON sl.key_id = k.id "
        "WHERE k.wallet = :wallet "
        "ORDER BY sl.created_at DESC LIMIT :limit",
        {"wallet": wallet_id, "limit": limit},
        SigningLog,
    )


async def count_recent_signings(
    key_id: str, extension_id: str, kind: int, seconds: int
) -> int:
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    result = await db.fetchone(
        "SELECT COUNT(*) as count FROM nsecbunker.signing_log "
        "WHERE key_id = :key_id AND extension_id = :extension_id "
        "AND kind = :kind AND created_at > :cutoff",
        {
            "key_id": key_id,
            "extension_id": extension_id,
            "kind": kind,
            "cutoff": cutoff,
        },
    )
    return result[0] if result else 0
