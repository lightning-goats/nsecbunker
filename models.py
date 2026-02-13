from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class BunkerKey(BaseModel):
    id: str
    user_id: str
    pubkey_hex: str
    encrypted_nsec: str
    created_at: datetime


class BunkerPermission(BaseModel):
    id: str
    user_id: str
    extension_id: str
    key_id: str
    kind: int
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None
    created_at: datetime


class SigningLog(BaseModel):
    id: str
    key_id: str
    extension_id: str
    kind: int
    event_id: str
    created_at: datetime


class CreateKeyData(BaseModel):
    private_key: str


class CreatePermissionData(BaseModel):
    extension_id: str
    key_id: str
    kind: int
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None


class UpdatePermissionData(BaseModel):
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None


class SignEventData(BaseModel):
    extension_id: str
    event: dict
