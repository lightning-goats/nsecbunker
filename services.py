from loguru import logger
from pynostr.event import Event

from .crud import (
    count_recent_signings,
    create_signing_log,
    get_decrypted_private_key,
    get_key,
    get_keys,
    get_permission_for_signing,
)


async def sign_event(
    user_id: str,
    extension_id: str,
    unsigned_event: dict,
    key_id: str | None = None,
) -> dict:
    """
    Sign a Nostr event using the Bunker.

    Args:
        user_id: LNBits account ID
        extension_id: Machine name of the calling extension
        unsigned_event: Dict with kind, tags, content (pubkey optional)
        key_id: Specific key ID to use (optional, defaults to user's first key)

    Returns:
        Complete signed event dict with id and sig fields added.

    Raises:
        PermissionError: Extension lacks permission for this event kind.
        LookupError: No key configured for this user.
    """
    # 1. Get key
    if key_id:
        key = await get_key(key_id)
        if not key or key.user_id != user_id:
            raise LookupError(f"Key {key_id} not found for user")
    else:
        keys = await get_keys(user_id)
        if not keys:
            raise LookupError("No keys configured for this user")
        key = keys[0]

    kind = unsigned_event.get("kind", 1)

    # 2. Check permission
    perm = await get_permission_for_signing(user_id, extension_id, kind)
    if not perm:
        raise PermissionError(
            f"Extension '{extension_id}' lacks permission for kind {kind}"
        )

    # 3. Check rate limit
    if perm.rate_limit_count and perm.rate_limit_seconds:
        recent = await count_recent_signings(
            key.id, extension_id, kind, perm.rate_limit_seconds
        )
        if recent >= perm.rate_limit_count:
            raise PermissionError(
                f"Rate limit exceeded: {perm.rate_limit_count} "
                f"per {perm.rate_limit_seconds}s"
            )

    # 4. Decrypt key
    private_key_hex = await get_decrypted_private_key(key.id)

    # 5. Sign event
    tags = unsigned_event.get("tags", [])
    content = unsigned_event.get("content", "")

    event = Event(
        kind=kind,
        tags=tags,
        content=content,
        public_key=key.pubkey_hex,
    )
    event.sign(private_key_hex)
    signed = event.to_dict()

    # 6. Log signing
    event_id = signed.get("id", "")
    await create_signing_log(key.id, extension_id, kind, event_id)
    logger.info(
        f"nsecbunker: signed kind:{kind} for {extension_id} "
        f"(key {key.id[:8]}..., event {event_id[:12]}...)"
    )

    # 7. Return signed event
    return signed


async def get_user_pubkey(user_id: str, key_id: str | None = None) -> str | None:
    """Get a user's public key hex."""
    if key_id:
        key = await get_key(key_id)
        if key and key.user_id == user_id:
            return key.pubkey_hex
        return None
    keys = await get_keys(user_id)
    if keys:
        return keys[0].pubkey_hex
    return None
