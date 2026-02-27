from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class BunkerKey(BaseModel):
    id: str
    wallet: str
    pubkey_hex: str
    encrypted_nsec: str
    label: Optional[str] = None
    created_at: datetime


class BunkerPermission(BaseModel):
    id: str
    wallet: str
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
    label: Optional[str] = None


class CreatePermissionData(BaseModel):
    extension_id: str
    key_id: str
    kind: int
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None


class UpdatePermissionData(BaseModel):
    rate_limit_count: Optional[int] = None
    rate_limit_seconds: Optional[int] = None


class QuickSetupData(BaseModel):
    extension_id: str
    key_id: str
    use_recommended_limits: bool = True


class SignEventData(BaseModel):
    extension_id: str
    event: dict


class UpdateKeyData(BaseModel):
    label: Optional[str] = None


class Nip04EncryptData(BaseModel):
    key_id: str
    pubkey: str
    plaintext: str


class Nip04DecryptData(BaseModel):
    key_id: str
    pubkey: str
    ciphertext: str


class Nip44EncryptData(BaseModel):
    key_id: str
    pubkey: str
    plaintext: str


class Nip44DecryptData(BaseModel):
    key_id: str
    pubkey: str
    payload: str
