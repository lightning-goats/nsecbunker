from lnbits.db import Connection


async def m001_initial(db: Connection):
    """
    Initial nsec bunker tables: keys, permissions, signing_log.
    """
    await db.execute(
        """
        CREATE TABLE nsecbunker.keys (
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
        CREATE TABLE nsecbunker.permissions (
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
        ON nsecbunker.permissions (user_id, extension_id, kind);
        """
    )

    await db.execute(
        """
        CREATE TABLE nsecbunker.signing_log (
            id TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            extension_id TEXT NOT NULL,
            kind INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


async def m002_wallet_scoping(db: Connection):
    """
    Rename user_id to wallet in keys and permissions tables
    so each wallet has its own independent settings.
    """
    # --- keys ---
    await db.execute(
        "ALTER TABLE nsecbunker.keys RENAME TO keys_m001"
    )
    await db.execute(
        """
        CREATE TABLE nsecbunker.keys (
            id TEXT PRIMARY KEY,
            wallet TEXT NOT NULL,
            pubkey_hex TEXT NOT NULL,
            encrypted_nsec TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    await db.execute(
        """
        INSERT INTO nsecbunker.keys (id, wallet, pubkey_hex, encrypted_nsec, created_at)
        SELECT id, user_id, pubkey_hex, encrypted_nsec, created_at
        FROM nsecbunker.keys_m001
        """
    )
    await db.execute("DROP TABLE nsecbunker.keys_m001")

    # --- permissions ---
    await db.execute(
        "DROP INDEX IF EXISTS nsecbunker.idx_permissions_user_ext"
    )
    await db.execute(
        "ALTER TABLE nsecbunker.permissions RENAME TO permissions_m001"
    )
    await db.execute(
        """
        CREATE TABLE nsecbunker.permissions (
            id TEXT PRIMARY KEY,
            wallet TEXT NOT NULL,
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
        INSERT INTO nsecbunker.permissions
            (id, wallet, extension_id, key_id, kind,
             rate_limit_count, rate_limit_seconds, created_at)
        SELECT id, user_id, extension_id, key_id, kind,
               rate_limit_count, rate_limit_seconds, created_at
        FROM nsecbunker.permissions_m001
        """
    )
    await db.execute("DROP TABLE nsecbunker.permissions_m001")

    await db.execute(
        """
        CREATE INDEX idx_permissions_wallet_ext
        ON nsecbunker.permissions (wallet, extension_id, kind);
        """
    )
