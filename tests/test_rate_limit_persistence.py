import asyncio
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from lnbits.db import Database
from lnbits.extensions.nsecbunker import crud


def test_rate_limit_check_and_log_are_one_database_operation(tmp_path):
    async def run_test():
        test_db = Database("ext_nsecbunker_rate_limit_test")
        await test_db.engine.dispose()
        test_db.path = str(tmp_path / "rate-limit.sqlite3")
        test_db.schema = "nsecbunker"
        test_db.engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=NullPool,
        )
        original_db = crud.db
        crud.db = test_db

        try:
            await test_db.execute(
                """
                CREATE TABLE nsecbunker.permissions (
                    id TEXT PRIMARY KEY,
                    wallet TEXT NOT NULL,
                    extension_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    kind INTEGER NOT NULL,
                    rate_limit_count INTEGER,
                    rate_limit_seconds INTEGER,
                    created_at TIMESTAMP NOT NULL
                )
                """
            )
            await test_db.execute(
                """
                CREATE TABLE nsecbunker.signing_log (
                    id TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL,
                    extension_id TEXT NOT NULL,
                    kind INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                )
                """
            )
            await test_db.execute(
                """
                INSERT INTO nsecbunker.permissions
                    (id, wallet, extension_id, key_id, kind,
                     rate_limit_count, rate_limit_seconds, created_at)
                VALUES
                    (:id, :wallet, :extension_id, :key_id, :kind,
                     :rate_limit_count, :rate_limit_seconds, :created_at)
                """,
                {
                    "id": "permission-1",
                    "wallet": "wallet-1",
                    "extension_id": "consumer",
                    "key_id": "key-1",
                    "kind": 1,
                    "rate_limit_count": 1,
                    "rate_limit_seconds": 60,
                    "created_at": datetime.now(timezone.utc),
                },
            )

            first = await crud.create_rate_limited_signing_log(
                "permission-1",
                "key-1",
                "consumer",
                1,
                "event-1",
                1,
                60,
            )
            second = await crud.create_rate_limited_signing_log(
                "permission-1",
                "key-1",
                "consumer",
                1,
                "event-2",
                1,
                60,
            )
            row = await test_db.fetchone(
                "SELECT COUNT(*) AS count FROM nsecbunker.signing_log"
            )

            assert first is not None
            assert second is None
            assert row["count"] == 1
        finally:
            crud.db = original_db
            await test_db.engine.dispose()

    asyncio.run(run_test())
