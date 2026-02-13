from lnbits.db import Connection


async def m001_initial(db: Connection):
    """
    Initial nsec bunker tables: keys, permissions, signing_log.
    """
    await db.execute(
        """
        CREATE TABLE bunker.keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            pubkey_hex TEXT NOT NULL,
            encrypted_nsec TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    await db.execute(
        """
        CREATE TABLE bunker.permissions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            extension_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            kind INTEGER NOT NULL,
            rate_limit_count INTEGER,
            rate_limit_seconds INTEGER,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    await db.execute(
        """
        CREATE INDEX idx_permissions_user_ext
        ON bunker.permissions (user_id, extension_id, kind);
        """
    )

    await db.execute(
        """
        CREATE TABLE bunker.signing_log (
            id TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            extension_id TEXT NOT NULL,
            kind INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
