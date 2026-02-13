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
from .discovery import discover_signing_requirements
from .helpers import parse_nostr_private_key
from .models import (
    BunkerKey,
    BunkerPermission,
    CreateKeyData,
    CreatePermissionData,
    QuickSetupData,
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

    key = await create_key(wallet.wallet.id, data)
    # Don't return the encrypted nsec in the response
    key.encrypted_nsec = ""
    return key


@nsecbunker_api_router.get("/api/v1/keys")
async def api_get_keys(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerKey]:
    keys = await get_keys(wallet.wallet.id)
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
    key = await create_key(wallet.wallet.id, data)
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
    return await create_permission(wallet.wallet.id, data)


@nsecbunker_api_router.get("/api/v1/permissions")
async def api_get_permissions(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerPermission]:
    return await get_permissions(wallet.wallet.id)


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


# --- Discovery & Quick Setup ---


@nsecbunker_api_router.get("/api/v1/discover")
async def api_discover(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[dict]:
    discovered = discover_signing_requirements()
    existing = await get_permissions(wallet.wallet.id)

    granted_set = {
        (p.extension_id, p.kind) for p in existing
    }

    result = []
    for ext in discovered:
        reqs = []
        for req in ext.requirements:
            reqs.append({
                "kind": req.kind,
                "kind_label": req.kind_label,
                "description": req.description,
                "required": req.required,
                "recommended_rate_limit": (
                    req.recommended_rate_limit.dict()
                    if req.recommended_rate_limit
                    else None
                ),
                "already_granted": (ext.extension_id, req.kind) in granted_set,
            })
        result.append({
            "extension_id": ext.extension_id,
            "extension_name": ext.extension_name,
            "requirements": reqs,
        })
    return result


@nsecbunker_api_router.post(
    "/api/v1/quick-setup", status_code=HTTPStatus.CREATED
)
async def api_quick_setup(
    data: QuickSetupData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[BunkerPermission]:
    discovered = discover_signing_requirements()
    ext_info = next(
        (e for e in discovered if e.extension_id == data.extension_id), None
    )
    if not ext_info:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No signing requirements found for '{data.extension_id}'.",
        )

    existing = await get_permissions(wallet.wallet.id)
    granted_set = {
        (p.extension_id, p.kind) for p in existing if p.key_id == data.key_id
    }

    created: list[BunkerPermission] = []
    for req in ext_info.requirements:
        if (data.extension_id, req.kind) in granted_set:
            continue

        rate_count = None
        rate_seconds = None
        if data.use_recommended_limits and req.recommended_rate_limit:
            rate_count = req.recommended_rate_limit.count
            rate_seconds = req.recommended_rate_limit.seconds

        perm_data = CreatePermissionData(
            extension_id=data.extension_id,
            key_id=data.key_id,
            kind=req.kind,
            rate_limit_count=rate_count,
            rate_limit_seconds=rate_seconds,
        )
        perm = await create_permission(wallet.wallet.id, perm_data)
        created.append(perm)

    return created


# --- Sign ---


@nsecbunker_api_router.post("/api/v1/sign")
async def api_sign_event(
    data: SignEventData,
    wallet: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    try:
        signed = await sign_event(
            wallet_id=wallet.wallet.id,
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
    return await get_signing_logs(wallet.wallet.id)
