# Technical Specification: LNBits Nsec Bunker Extension

**Version:** 2.0
**Authors:** Gemini / Sat / Claude
**Date:** February 13, 2026

## 1. Introduction & Vision

### 1.1. Problem Statement

The proliferation of Nostr-related extensions within LNBits creates a security
challenge and a fragmented user experience. Each extension must either ask the
user for their Nostr private key (nsec) or manage its own key pair, increasing
the attack surface and forcing users to place trust in multiple, disparate
pieces of software. This hinders the development of automated, long-running
applications that require Nostr signing capabilities.

### 1.2. Proposed Solution

The Nsec Bunker is a specialized LNBits extension designed to act as a secure,
system-wide vault for users' Nostr private keys. It will serve as a centralized
signing oracle for all other extensions. Instead of handling private keys, other
extensions will delegate event signing to the Bunker via a secure internal API,
governed by a granular, user-controlled permissions system. This architecture
drastically enhances security, simplifies development for other extensions, and
provides a seamless user experience.

## 2. Core Architecture & Workflow

The Bunker operates on the principle of key isolation. Private keys are
encrypted and stored within the Bunker's dedicated database tables, partitioned
on a per-user basis, leveraging the LNBits multi-user environment.

### 2.1. Operating Modes

The Bunker supports two operating modes per key:

- **Auto-Sign Mode** (default): The key is encrypted at rest using LNBits'
  built-in `encrypt_internal_message()` (AES-256-CBC keyed to
  `settings.auth_secret_key`). Any extension with an approved permission can
  trigger signing without user interaction. This is the mode required for
  automated extensions like CyberHerd and SplitPayments that sign events 24/7.

- **Interactive Mode** (optional): The key is additionally encrypted with a
  user-supplied password via PBKDF2-HMAC-SHA256 + AES-256-GCM. Requires manual
  unlock via the UI before any signing can occur. Suitable for high-security
  keys where the user wants to control each signing session. Not suitable for
  automated/unattended extensions.

### 2.2. Auto-Sign Workflow

1. **Key Import:** User navigates to the Nsec Bunker extension and imports an
   existing nsec (hex or bech32 format) or generates a new keypair.
2. **Secure Storage:** The nsec is encrypted via `encrypt_internal_message()`
   and stored in the database. The plaintext nsec is not retained in memory
   beyond the import operation.
3. **Permission Grant:** User proactively grants permissions to specific
   extensions for specific event kinds via the Permissions Dashboard.
4. **Signing Request:** An extension (e.g., SplitPayments) needs a Nostr event
   signed. It calls the Bunker's Python API:
   `await sign_event(user_id, "splitpayments", unsigned_event)`.
5. **Permission Check:** The Bunker checks if the requesting extension has
   pre-approved permission for the specific event kind.
   - **If approved:** Decrypt key, sign event, log the operation, return signed
     event.
   - **If denied:** Return 403 immediately. The user must grant permission via
     the Bunker UI first.
6. **Response:** The Bunker returns the complete, signed event object to the
   requesting extension, which is then responsible for publishing it to relays.

### 2.3. Interactive Workflow

1. **Key Import:** Same as auto-sign, but user also provides an unlock
   password. The nsec is encrypted with both the server key
   (`encrypt_internal_message()`) and the user's password (PBKDF2 + AES-256-GCM).
   Only the password-encrypted copy is used for signing; the server-encrypted
   copy is kept only for key recovery by the server admin.
2. **Unlock:** User enters their password in the Bunker UI. The derived
   encryption key is cached in an in-memory TTL store (keyed by user_id) for a
   configurable duration (default: 15 minutes of inactivity).
3. **Signing:** Same permission checks as auto-sign, but additionally requires
   that the user's session is unlocked. If locked, the API returns 423 (Locked).
4. **Lock:** User can explicitly lock the bunker, or it locks automatically when
   the TTL expires. Locking purges the cached derived key from memory.

## 3. Database Schema

The extension creates three tables in the `bunker` schema, partitioned by
LNBits account ID (`user_id`).

### 3.1. `bunker.keys`

Stores the user's encrypted Nostr keys.

| Column | Type | Constraints | Description |
|:---|:---|:---|:---|
| `id` | TEXT | PRIMARY KEY | Unique identifier (urlsafe_short_hash) |
| `user_id` | TEXT | NOT NULL | LNBits account ID (from wallet auth) |
| `pubkey_hex` | TEXT | NOT NULL | Public key in hex format |
| `encrypted_nsec` | TEXT | NOT NULL | nsec encrypted via `encrypt_internal_message()` |
| `password_encrypted_nsec` | TEXT | NULL | PBKDF2+AES-256-GCM encrypted copy (interactive mode only) |
| `salt` | TEXT | NULL | Cryptographic salt for PBKDF2 (interactive mode only) |
| `nonce` | TEXT | NULL | AES-GCM nonce (interactive mode only) |
| `mode` | TEXT | NOT NULL DEFAULT 'auto' | Operating mode: `auto` or `interactive` |
| `created_at` | TIMESTAMP | NOT NULL | Timestamp of creation |

### 3.2. `bunker.permissions`

Stores the permissions granted by users to other extensions.

| Column | Type | Constraints | Description |
|:---|:---|:---|:---|
| `id` | TEXT | PRIMARY KEY | Unique identifier (urlsafe_short_hash) |
| `user_id` | TEXT | NOT NULL | LNBits account ID |
| `extension_id` | TEXT | NOT NULL | Machine name of the requesting extension (e.g., `splitpayments`) |
| `key_id` | TEXT | NOT NULL | Foreign key to `bunker.keys.id` |
| `kind` | INTEGER | NOT NULL | Nostr event kind this permission applies to |
| `rate_limit_count` | INTEGER | NULL | Max signing requests per time window |
| `rate_limit_seconds` | INTEGER | NULL | Time window for rate limit (e.g., 86400 for one day) |
| `created_at` | TIMESTAMP | NOT NULL | When permission was granted |

**Index:** `CREATE INDEX idx_permissions_user_ext ON bunker.permissions (user_id, extension_id, kind);`

### 3.3. `bunker.signing_log`

Audit trail for all signing operations.

| Column | Type | Constraints | Description |
|:---|:---|:---|:---|
| `id` | TEXT | PRIMARY KEY | Unique identifier |
| `key_id` | TEXT | NOT NULL | Foreign key to `bunker.keys.id` |
| `extension_id` | TEXT | NOT NULL | Which extension requested signing |
| `kind` | INTEGER | NOT NULL | Event kind that was signed |
| `event_id` | TEXT | NOT NULL | The Nostr event ID that was produced |
| `created_at` | TIMESTAMP | NOT NULL | When signing occurred |

## 4. Security Specification

### 4.1. Auto-Sign Mode Encryption

Uses LNBits' built-in `encrypt_internal_message()` / `decrypt_internal_message()`
from `lnbits/helpers.py`. This is AES-256-CBC keyed to `settings.auth_secret_key`.
The trust model matches the existing custodial wallet system — if you trust
LNBits with your sats, you trust it with your nsec.

### 4.2. Interactive Mode Encryption

- **KDF:** PBKDF2-HMAC-SHA256 with a unique cryptographic salt per key and a
  minimum of 100,000 iterations.
- **Encryption:** AES-256-GCM providing confidentiality and authenticity.
- **Key Caching:** The derived encryption key (never the nsec) may be cached in
  an in-memory TTL dictionary (`{user_id: derived_key}`) for a configurable
  duration. The cache is process-local and cleared on server restart.

### 4.3. In-Memory Key Handling

The plaintext nsec must only exist in memory for the minimum time required for
the signing operation. Python's garbage collector handles deallocation; explicit
overwriting is best-effort since Python strings are immutable.

### 4.4. Sensitive Event Kinds

The following event kinds are flagged as sensitive. In interactive mode, they
always require a fresh unlock (bypassing the TTL cache). In auto-sign mode, a
warning is logged:

- `kind:0` — Set Metadata
- `kind:3` — Contact List
- `kind:10002` — Relay List Metadata
- `kind:22242` — Client Authentication

This list is configurable via the Bunker settings.

## 5. API Specification

### 5.1. Python Internal API (preferred for extension-to-extension)

LNBits extensions communicate via direct Python imports with lazy loading and
try/except guards. This is the established pattern used by CyberHerd,
SplitPayments, and Lightning Goats.

```python
# Consuming extension usage:
try:
    from lnbits.extensions.nsecbunker.services import sign_event
    signed = await sign_event(
        user_id="abc123",
        extension_id="splitpayments",
        unsigned_event={
            "pubkey": "hex...",
            "created_at": 1678886400,
            "kind": 9734,
            "tags": [["p", "hex..."]],
            "content": "Zap!"
        },
    )
except ImportError:
    # Nsec Bunker not installed — fall back to own key storage
    pass
except PermissionError:
    # No permission granted for this extension + kind
    pass
```

**Function signature:**
```python
async def sign_event(
    user_id: str,
    extension_id: str,
    unsigned_event: dict,
    key_id: str | None = None,  # optional, uses default key if omitted
) -> dict:
    """
    Sign a Nostr event using the Bunker.

    Args:
        user_id: LNBits account ID
        extension_id: Machine name of the calling extension
        unsigned_event: Dict with pubkey, created_at, kind, tags, content
        key_id: Specific key ID to use (optional, defaults to user's primary key)

    Returns:
        Complete signed event dict with id and sig fields added.

    Raises:
        PermissionError: Extension lacks permission for this event kind.
        LookupError: No key configured for this user.
        RuntimeError: Key is in interactive mode and bunker is locked.
    """
```

### 5.2. REST API

For external callers or extensions that prefer HTTP.

#### Sign Event

`POST /nsecbunker/api/v1/sign`

**Authentication:** `Depends(require_invoice_key)` — the calling extension
passes a wallet invoice key; the user is derived from the wallet.

**Request:**
```json
{
  "extension_id": "splitpayments",
  "event": {
    "pubkey": "hex...",
    "created_at": 1678886400,
    "kind": 1,
    "tags": [],
    "content": "Hello, Nostr!"
  }
}
```

**Success Response (200):**
```json
{
  "event": {
    "id": "hex...",
    "sig": "hex...",
    "pubkey": "hex...",
    "created_at": 1678886400,
    "kind": 1,
    "tags": [],
    "content": "Hello, Nostr!"
  }
}
```

**Error Responses:**
- `401` — Invalid or missing API key
- `403` — Extension lacks permission for this event kind
- `404` — No key configured for this user
- `423` — Key is in interactive mode and bunker is locked
- `429` — Rate limit exceeded

#### Key Management

- `POST /nsecbunker/api/v1/keys` — Import or generate key.
  Auth: `Depends(require_admin_key)`
- `GET /nsecbunker/api/v1/keys` — List user's keys (public info only).
  Auth: `Depends(require_admin_key)`
- `DELETE /nsecbunker/api/v1/keys/{key_id}` — Delete a key and its permissions.
  Auth: `Depends(require_admin_key)`

#### Permission Management

- `GET /nsecbunker/api/v1/permissions` — List all permissions for user.
  Auth: `Depends(require_admin_key)`
- `POST /nsecbunker/api/v1/permissions` — Grant a new permission.
  Auth: `Depends(require_admin_key)`
- `PUT /nsecbunker/api/v1/permissions/{perm_id}` — Edit rate limits.
  Auth: `Depends(require_admin_key)`
- `DELETE /nsecbunker/api/v1/permissions/{perm_id}` — Revoke a permission.
  Auth: `Depends(require_admin_key)`

#### Signing Log

- `GET /nsecbunker/api/v1/log` — Recent signing activity.
  Auth: `Depends(require_admin_key)`

## 6. Permissions Model

### 6.1. Principle of Least Privilege

Permissions are granted per-extension, per-event-kind. There is no wildcard
"sign anything" permission.

### 6.2. Proactive Grant Only

Permissions must be granted by the user before an extension attempts to sign.
If an extension calls `sign_event()` without permission, it receives a
`PermissionError` / 403 immediately. There is no interactive approval flow
during a signing request.

### 6.3. Rate Limiting

Each permission may optionally include:
- `rate_limit_count`: Maximum signing operations within the time window.
- `rate_limit_seconds`: The time window duration.

Rate limit state is tracked in-memory (reset on server restart) using a sliding
window counter keyed by `(user_id, extension_id, kind)`.

### 6.4. Sensitive Kinds

Kinds listed in Section 4.4 are flagged as sensitive. The UI shows a warning
when granting permanent permissions for these kinds.

## 7. User Interface

The UI follows LNBits extension conventions using Quasar (Vue.js) components.

### 7.1. Key Management Card

- Import nsec field accepting hex or `nsec1...` bech32 format
- "Generate New Key" button
- Display of public key in both hex and `npub1...` format
- Mode toggle: Auto-Sign / Interactive
- Delete key button with confirmation dialog

### 7.2. Permissions Dashboard

A table listing all granted permissions with columns:
- **Extension** — machine name of the extension
- **Event Kind** — the Nostr event kind number with human-readable label
- **Rate Limit** — display of count/window or "Unlimited"
- **Granted** — timestamp
- **Actions** — Edit (rate limits) and Revoke buttons

"Add Permission" form with:
- Extension name input (text, must match extension machine name)
- Event kind input (number)
- Optional rate limit fields

### 7.3. Signing Log

A table showing recent signing activity:
- **Time** — when the event was signed
- **Extension** — which extension requested it
- **Kind** — event kind
- **Event ID** — truncated Nostr event ID

### 7.4. Settings

Uses the built-in `lnbits-extension-settings-btn-dialog` component for:
- Configurable sensitive kinds list
- Default rate limits for new permissions
- Interactive mode TTL duration

## 8. Migration Path

### 8.1. Gradual Adoption

Extensions that currently store their own Nostr keys (lnurlp, splitpayments,
cyberherd) can adopt the Bunker gradually using the lazy-import pattern:

```python
async def get_signing_key(user_id: str, own_key: str | None) -> str | None:
    """Try Bunker first, fall back to own key storage."""
    try:
        from lnbits.extensions.nsecbunker.services import get_user_key_hex
        bunker_key = await get_user_key_hex(user_id)
        if bunker_key:
            return bunker_key
    except ImportError:
        pass
    return own_key
```

### 8.2. Key Import Helper

The Bunker provides a one-click migration in its UI: "Import key from
[extension name]" that reads the key from the other extension's storage and
imports it into the Bunker.

### 8.3. No Breaking Changes

Existing extensions continue to work with their own key storage. Bunker
adoption is opt-in. Extensions should check for the Bunker first and fall back
to their own storage if it's not installed.

## 9. Implementation Order

1. `models.py` — Data models for keys, permissions, signing log, settings
2. `migrations.py` — Database schema creation (`m001_initial`)
3. `crud.py` — CRUD operations for keys, permissions, signing log
4. `helpers.py` — Key parsing, PBKDF2 derivation, AES-GCM encrypt/decrypt
5. `services.py` — Core signing logic, permission checks, rate limiting
6. `views_api.py` — REST API endpoints
7. `views.py` — HTML view serving the UI template
8. `templates/nsecbunker/index.html` — Quasar/Vue UI
9. `static/js/index.js` — Frontend logic
10. `tasks.py` — Background tasks (signing log cleanup, rate limit reset)
11. `__init__.py` — Extension registration and router setup
