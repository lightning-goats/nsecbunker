from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from loguru import logger
from pynostr.key import PrivateKey

from .crud import (
    create_key,
    create_permission,
    delete_key,
    delete_permission,
    delete_permissions_for_key,
    get_keys,
    get_permissions,
    get_signing_logs,
    update_permission,
)
from .helpers import parse_nostr_private_key
from .models import (
    BunkerKey,
    BunkerPermission,
    CreateKeyData,
    CreatePermissionData,
    SignEventData,
    SigningLog,
    UpdatePermissionData,
)
from .services import sign_event

nsecbunker_api_router = APIRouter()


# --- Keys ---


@nsecbunker_api_router.post(
    "/api/v1/keys", status_code=HTTPStatus.CREATED
)
async def api_create_key(
    data: CreateKeyData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> BunkerKey:
    try:
        parse_nostr_private_key(data.private_key)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid Nostr private key.",
        ) from exc

    key = await create_key(wallet.wallet.user, data)
    # Don't return the encrypted nsec in the response
    key.encrypted_nsec = ""
    return key


@nsecbunker_api_router.get("/api/v1/keys")
async def api_get_keys(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerKey]:
    keys = await get_keys(wallet.wallet.user)
    # Strip encrypted secrets from response
    for key in keys:
        key.encrypted_nsec = ""
    return keys


@nsecbunker_api_router.delete(
    "/api/v1/keys/{key_id}", status_code=HTTPStatus.OK
)
async def api_delete_key(
    key_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    # Cascade: delete permissions first, then the key
    await delete_permissions_for_key(key_id)
    await delete_key(key_id)


# --- Keys: Generate ---


@nsecbunker_api_router.post(
    "/api/v1/keys/generate", status_code=HTTPStatus.CREATED
)
async def api_generate_key(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> BunkerKey:
    private_key = PrivateKey()
    data = CreateKeyData(private_key=private_key.hex())
    key = await create_key(wallet.wallet.user, data)
    key.encrypted_nsec = ""
    return key


# --- Permissions ---


@nsecbunker_api_router.post(
    "/api/v1/permissions", status_code=HTTPStatus.CREATED
)
async def api_create_permission(
    data: CreatePermissionData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> BunkerPermission:
    return await create_permission(wallet.wallet.user, data)


@nsecbunker_api_router.get("/api/v1/permissions")
async def api_get_permissions(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerPermission]:
    return await get_permissions(wallet.wallet.user)


@nsecbunker_api_router.put(
    "/api/v1/permissions/{perm_id}", status_code=HTTPStatus.OK
)
async def api_update_permission(
    perm_id: str,
    data: UpdatePermissionData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> BunkerPermission:
    try:
        return await update_permission(perm_id, data)
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=str(exc),
        ) from exc


@nsecbunker_api_router.delete(
    "/api/v1/permissions/{perm_id}", status_code=HTTPStatus.OK
)
async def api_delete_permission(
    perm_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    await delete_permission(perm_id)


# --- Sign ---


@nsecbunker_api_router.post("/api/v1/sign")
async def api_sign_event(
    data: SignEventData,
    wallet: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    try:
        signed = await sign_event(
            user_id=wallet.wallet.user,
            extension_id=data.extension_id,
            unsigned_event=data.event,
        )
        return {"event": signed}
    except LookupError as exc:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PermissionError as exc:
        detail = str(exc)
        if "Rate limit" in detail:
            raise HTTPException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                detail=detail,
            ) from exc
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail=detail,
        ) from exc
    except Exception as exc:
        logger.error(f"nsecbunker: sign_event failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Signing failed.",
        ) from exc


# --- Signing Log ---


@nsecbunker_api_router.get("/api/v1/log")
async def api_get_logs(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[SigningLog]:
    return await get_signing_logs(wallet.wallet.user)
