from __future__ import annotations

import asyncio
import contextlib
import csv
import datetime as dt
import functools
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import time
import zipfile
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Literal, Optional

import discord
from discord import app_commands
from discord.ext import tasks

LOG = logging.getLogger("audit-archiver")
DISCORD_EPOCH_MS = 1_420_070_400_000


def bounded_env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: Optional[int] = None,
) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer; got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}; got {raw!r}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}; got {raw!r}")
    return value


DB_PATH = Path(os.getenv("AUDIT_DB", "audit_logs.db"))
DISK_MIN_FREE_BYTES = bounded_env_int(
    "AUDIT_DISK_MIN_FREE_BYTES", 2 * 1024**3, minimum=0
)
STAGING_BATCH_SIZE = max(
    1, min(50, int(os.getenv("AUDIT_STAGING_BATCH_SIZE", "50")))
)
STAGING_FLUSH_SECONDS = 0.2
STAGING_ADMISSION_TIMEOUT_SECONDS = 1.0
STAGING_WRITE_RETRIES = 5
STAGING_CONSUME_SIZE = 500
STATS_CACHE_SECONDS = 60.0
RETENTION_PRUNE_BATCH_SIZE = 1000
EXPORT_BATCH_SIZE = 5000
EXPORT_PART_MAX_ROWS = 100_000
EXPORT_PART_MAX_BYTES = 20 * 1024**2
EXPORT_ATTACHMENT_MAX_BYTES = 25 * 1024**2
EXPORT_CSV_HEADER = (
    "条目ID",
    "时间(UTC)",
    "操作类型",
    "操作类型码",
    "操作者ID",
    "目标ID",
    "理由",
    "来源",
    "完整数据",
)
SYNC_INTERVAL_MINUTES = bounded_env_int(
    "AUDIT_SYNC_INTERVAL_MINUTES", 10, minimum=1, maximum=1440
)
REPLAY_OVERLAP_SECONDS = bounded_env_int(
    "AUDIT_REPLAY_OVERLAP_SECONDS", 300, minimum=0, maximum=86400
)
AUDIT_RETENTION_DAYS = bounded_env_int(
    "AUDIT_RETENTION_DAYS", 0, minimum=0
)
AUDIT_VACUUM_AFTER_PRUNE = os.getenv(
    "AUDIT_VACUUM_AFTER_PRUNE", "false"
).strip().lower() in {"1", "true", "yes", "on"}
STAGING_BACKLOG_WARN = bounded_env_int(
    "AUDIT_STAGING_BACKLOG_WARN", 50000, minimum=1
)
SQLITE_SYNCHRONOUS = os.getenv("SQLITE_SYNCHRONOUS", "FULL").upper()
SCHEMA_VERSION = 5
COMMAND_SYNC_MODE = os.getenv("AUDIT_COMMAND_SYNC_MODE", "none").strip().lower()
ALLOW_VIEW_AUDIT_LOG_PERMISSION = os.getenv(
    "AUDIT_ALLOW_VIEW_LOG_PERMISSION", "false"
).strip().lower() in {"1", "true", "yes", "on"}
TARGET_GUILDS = {
    int(value)
    for value in os.getenv("TARGET_GUILD_IDS", "").split(",")
    if value.strip()
}
COMMAND_GUILD_IDS = {
    int(value)
    for value in os.getenv("AUDIT_COMMAND_GUILD_IDS", "").split(",")
    if value.strip()
} or TARGET_GUILDS


def disk_free_bytes() -> int:
    try:
        filesystem = os.statvfs(DB_PATH)
    except OSError:
        LOG.warning(
            "Could not determine free disk space for %s",
            DB_PATH,
            exc_info=True,
        )
        return 2**63 - 1
    return int(filesystem.f_bavail) * int(filesystem.f_frsize)


SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_entries (
    guild_id             INTEGER NOT NULL,
    entry_id             INTEGER NOT NULL,
    action_type          INTEGER NOT NULL,
    user_id              INTEGER,
    target_id            INTEGER,
    created_at_ms        INTEGER NOT NULL,
    reason               TEXT,
    payload_json         TEXT NOT NULL,
    first_received_at_ms INTEGER NOT NULL,
    last_seen_at_ms      INTEGER NOT NULL,
    source_rank          INTEGER NOT NULL,
    last_source          TEXT NOT NULL,
    PRIMARY KEY (guild_id, entry_id)
) WITHOUT ROWID;

-- The primary key already supports per-guild entry_id range scans in both
-- directions. Convert time bounds to snowflakes instead of duplicating it.
CREATE INDEX IF NOT EXISTS idx_audit_action
    ON audit_entries(guild_id, action_type, entry_id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user
    ON audit_entries(guild_id, user_id, entry_id DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_entries(guild_id, target_id, entry_id DESC)
    WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_user_action
    ON audit_entries(guild_id, user_id, action_type, entry_id DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_target_action
    ON audit_entries(guild_id, target_id, action_type, entry_id DESC)
    WHERE target_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS sync_state (
    guild_id                 INTEGER PRIMARY KEY,
    last_backfill_entry_id   INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_roles (
    guild_id     INTEGER NOT NULL,
    role_id      INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (guild_id, role_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS staging_entries (
    staging_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id       INTEGER NOT NULL,
    entry_id       INTEGER NOT NULL,
    payload_json   TEXT NOT NULL,
    received_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staging_scan
    ON staging_entries(staging_id);

CREATE TABLE IF NOT EXISTS audit_dead_letters (
    guild_id        INTEGER NOT NULL,
    entry_id        INTEGER NOT NULL,
    source          TEXT NOT NULL,
    error_type      TEXT,
    error_text      TEXT,
    first_seen_at_ms INTEGER NOT NULL,
    last_seen_at_ms INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (guild_id, entry_id, source)
);
"""

DEAD_LETTER_UPSERT_SQL = """
INSERT INTO audit_dead_letters (
    guild_id, entry_id, source, error_type, error_text,
    first_seen_at_ms, last_seen_at_ms, attempts
) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT(guild_id, entry_id, source) DO UPDATE SET
    error_type = excluded.error_type,
    error_text = excluded.error_text,
    last_seen_at_ms = excluded.last_seen_at_ms,
    attempts = audit_dead_letters.attempts + 1;
"""

UPSERT_SQL = """
INSERT INTO audit_entries (
    guild_id, entry_id, action_type, user_id, target_id, created_at_ms,
    reason, payload_json, first_received_at_ms, last_seen_at_ms,
    source_rank, last_source
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(guild_id, entry_id) DO UPDATE SET
    action_type = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        THEN excluded.action_type ELSE audit_entries.action_type END,
    user_id = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        AND excluded.user_id IS NOT NULL
        THEN excluded.user_id ELSE audit_entries.user_id END,
    target_id = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        AND excluded.target_id IS NOT NULL
        THEN excluded.target_id ELSE audit_entries.target_id END,
    created_at_ms = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        THEN excluded.created_at_ms ELSE audit_entries.created_at_ms END,
    reason = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        AND excluded.reason IS NOT NULL
        THEN excluded.reason ELSE audit_entries.reason END,
    payload_json = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        AND excluded.payload_json IS NOT NULL
        THEN excluded.payload_json ELSE audit_entries.payload_json END,
    last_seen_at_ms = MAX(audit_entries.last_seen_at_ms, excluded.last_seen_at_ms),
    source_rank = MAX(audit_entries.source_rank, excluded.source_rank),
    last_source = CASE WHEN excluded.source_rank >= audit_entries.source_rank
        THEN excluded.last_source ELSE audit_entries.last_source END;
"""


@dataclass(slots=True)
class AuditRow:
    guild_id: int
    entry_id: int
    action_type: int
    user_id: Optional[int]
    target_id: Optional[int]
    created_at_ms: int
    reason: Optional[str]
    payload_json: str
    first_received_at_ms: int
    last_seen_at_ms: int
    source_rank: int
    last_source: str

    def values(self) -> tuple[Any, ...]:
        return (
            self.guild_id,
            self.entry_id,
            self.action_type,
            self.user_id,
            self.target_id,
            self.created_at_ms,
            self.reason,
            self.payload_json,
            self.first_received_at_ms,
            self.last_seen_at_ms,
            self.source_rank,
            self.last_source,
        )


@dataclass(frozen=True, slots=True)
class DeadLetter:
    guild_id: int
    entry_id: int
    source: str
    error_type: str
    error_text: str
    seen_at_ms: int

    def values(self) -> tuple[Any, ...]:
        return (
            self.guild_id,
            self.entry_id,
            self.source,
            self.error_type,
            self.error_text,
            self.seen_at_ms,
            self.seen_at_ms,
        )


@dataclass(frozen=True, slots=True)
class StagingConsumeResult:
    consumed_count: int
    invalid_count: int
    invalid_by_guild: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class AuditQuery:
    guild_id: int
    filter_column: Literal["user_id", "target_id"]
    subject_id: int
    action_type: Optional[int]
    lower_entry_id: Optional[int]
    upper_entry_id: Optional[int]
    page_size: int
    cursor: Optional[int] = None


@dataclass(frozen=True, slots=True)
class AuditExportQuery:
    guild_id: int
    action_type: Optional[int]
    lower_entry_id: Optional[int]
    upper_entry_id: Optional[int]
    user_id: Optional[int]
    target_id: Optional[int]


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def checked_sqlite_int(value: Any, field: str) -> int:
    converted = int(value)
    if not -(2**63) <= converted <= 2**63 - 1:
        raise OverflowError(f"{field} is outside SQLite's integer range")
    return converted


def staged_payload_to_row(
    guild_id: int,
    entry_id: int,
    payload_json: str,
    received_at_ms: int,
) -> AuditRow:
    payload = json.loads(payload_json)
    if not isinstance(payload, dict):
        raise ValueError("staging payload must be a JSON object")
    guild_id = checked_sqlite_int(guild_id, "guild_id")
    entry_id = checked_sqlite_int(entry_id, "entry_id")
    received_at_ms = checked_sqlite_int(received_at_ms, "received_at_ms")
    if (
        checked_sqlite_int(payload["guild_id"], "payload.guild_id") != guild_id
        or checked_sqlite_int(payload["entry_id"], "payload.entry_id") != entry_id
    ):
        raise ValueError("staging payload identifiers do not match its columns")
    reason = payload.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise TypeError("staging reason must be a string or null")
    user_id = payload.get("user_id")
    target_id = payload.get("target_id")
    return AuditRow(
        guild_id=guild_id,
        entry_id=entry_id,
        action_type=checked_sqlite_int(payload["action_type"], "action_type"),
        user_id=(
            None if user_id is None else checked_sqlite_int(user_id, "user_id")
        ),
        target_id=(
            None if target_id is None else checked_sqlite_int(target_id, "target_id")
        ),
        created_at_ms=checked_sqlite_int(
            payload.get("created_at_ms", snowflake_ms(entry_id)),
            "created_at_ms",
        ),
        reason=reason,
        payload_json=payload_json,
        first_received_at_ms=received_at_ms,
        last_seen_at_ms=received_at_ms,
        source_rank=0,
        last_source="gateway",
    )


def snowflake_ms(snowflake: int) -> int:
    return (snowflake >> 22) + DISCORD_EPOCH_MS


def jsonable(value: Any, *, depth: int = 0) -> Any:
    """Convert discord.py models to a bounded, stable JSON representation."""
    if depth > 7:
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.timezone.utc).isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, discord.Permissions):
        return value.value
    if isinstance(value, discord.PermissionOverwrite):
        allow, deny = value.pair()
        return {"allow": allow.value, "deny": deny.value}
    if isinstance(value, discord.Colour):
        return value.value
    if isinstance(value, discord.Asset):
        return str(value)

    enum_name = getattr(value, "name", None)
    enum_value = getattr(value, "value", None)
    if isinstance(enum_name, str) and enum_value is not None:
        return {
            "name": enum_name,
            "value": jsonable(enum_value, depth=depth + 1),
        }

    if isinstance(value, Mapping):
        return {
            str(key): jsonable(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [jsonable(item, depth=depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return [jsonable(item, depth=depth + 1) for item in value]

    object_id = getattr(value, "id", None)
    if object_id is not None:
        result: dict[str, Any] = {
            "id": int(object_id),
            "kind": type(value).__name__,
        }
        name = getattr(value, "name", None)
        if name is not None:
            result["name"] = str(name)
        return result

    invite_code = getattr(value, "code", None)
    if invite_code is not None:
        return {"code": str(invite_code), "kind": type(value).__name__}

    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        public = {
            key: jsonable(item, depth=depth + 1)
            for key, item in attributes.items()
            if not key.startswith("_")
        }
        if public:
            return public

    return str(value)


def dump_json(value: Any) -> str:
    return json.dumps(
        jsonable(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def public_attributes(value: Any) -> dict[str, Any]:
    attributes = getattr(value, "__dict__", None)
    if not isinstance(attributes, dict):
        return {}
    return {
        key: jsonable(item)
        for key, item in attributes.items()
        if not key.startswith("_")
    }


def normalise_extra(extra: Any) -> Any:
    if extra is None:
        return None

    object_id = getattr(extra, "id", None)
    if object_id is not None:
        return jsonable(extra)

    names = (
        "count",
        "channel",
        "message_id",
        "delete_member_days",
        "members_removed",
        "integration_type",
        "automod_rule_name",
        "automod_rule_trigger_type",
        "application_id",
    )
    result = {
        name: jsonable(getattr(extra, name))
        for name in names
        if hasattr(extra, name)
    }
    return result or jsonable(extra)


def resolved_user_target_id(target: Any) -> Optional[int]:
    """Return an ID only when discord.py resolved a concrete user target."""
    if isinstance(target, (discord.User, discord.Member, discord.ClientUser)):
        return int(target.id)
    return None


def entry_to_row(entry: discord.AuditLogEntry, source: str) -> AuditRow:
    seen_at = now_ms()

    try:
        changes = {
            "before": public_attributes(entry.before),
            "after": public_attributes(entry.after),
        }
    except Exception as exc:
        LOG.exception("Could not normalise changes for audit entry %s", entry.id)
        changes = {"conversion_error": type(exc).__name__}

    # Discord's raw target_id remains authoritative for every entity type. If it
    # is null, only a concrete User/Member target may supply a user-ID fallback;
    # channel, message, role, app, and generic Object IDs are never substituted.
    internal_target_id = getattr(entry, "_target_id", None)
    try:
        target = entry.target
    except Exception as exc:
        LOG.exception("Could not resolve target for audit entry %s", entry.id)
        target = None
        target_id = int(internal_target_id) if internal_target_id is not None else None
        target_json = {"conversion_error": type(exc).__name__}
    else:
        candidate = internal_target_id
        if candidate is None:
            candidate = resolved_user_target_id(target)
        target_id = int(candidate) if candidate is not None else None
        target_json = jsonable(target)

    options = normalise_extra(entry.extra)
    action_type = int(entry.action.value)
    payload = {
        "guild_id": entry.guild.id,
        "entry_id": entry.id,
        "action_type": action_type,
        "action_name": entry.action.name,
        "user_id": entry.user_id,
        "target_id": target_id,
        "target": target_json,
        "reason": entry.reason,
        "changes": changes,
        "options": options,
        "created_at_ms": snowflake_ms(entry.id),
    }

    source_rank = {
        "gateway": 0,
        "rest_backfill": 1,
        "rest_refresh": 2,
    }[source]
    return AuditRow(
        guild_id=entry.guild.id,
        entry_id=entry.id,
        action_type=action_type,
        user_id=entry.user_id,
        target_id=target_id,
        created_at_ms=snowflake_ms(entry.id),
        reason=entry.reason,
        payload_json=dump_json(payload),
        first_received_at_ms=seen_at,
        last_seen_at_ms=seen_at,
        source_rank=source_rank,
        last_source=source,
    )


class SQLiteStore:
    """One SQLite connection owned by one dedicated worker thread."""

    def __init__(self, path: Path):
        self.path = path
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="audit-sqlite")
        self._connection: Optional[sqlite3.Connection] = None

    async def _run(self, function: Any, *args: Any) -> Any:
        loop = asyncio.get_running_loop()
        call = functools.partial(function, *args)
        return await loop.run_in_executor(self._executor, call)

    async def open(self) -> None:
        await self._run(self._open)

    def _open(self) -> None:
        if SQLITE_SYNCHRONOUS not in {"FULL", "NORMAL"}:
            raise ValueError("SQLITE_SYNCHRONOUS must be FULL or NORMAL")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30.0)
        mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            connection.close()
            raise RuntimeError(f"Could not enable SQLite WAL mode: {mode}")
        connection.execute(f"PRAGMA synchronous={SQLITE_SYNCHRONOUS}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3, 4, SCHEMA_VERSION):
            connection.close()
            raise RuntimeError(f"Unsupported database schema version: {version}")
        if version in (0, 1):
            connection.executescript(
                """
                DROP INDEX IF EXISTS idx_audit_action;
                DROP INDEX IF EXISTS idx_audit_user;
                DROP INDEX IF EXISTS idx_audit_target;
                DROP INDEX IF EXISTS idx_audit_user_action;
                DROP INDEX IF EXISTS idx_audit_target_action;
                """
            )
        connection.executescript(SCHEMA)
        expected = {
            "guild_id", "entry_id", "action_type", "user_id", "target_id",
            "created_at_ms", "reason", "payload_json",
            "first_received_at_ms", "last_seen_at_ms", "source_rank", "last_source",
        }
        actual = {
            row[1]
            for row in connection.execute("PRAGMA table_info(audit_entries)")
        }
        if actual != expected:
            connection.close()
            raise RuntimeError(
                "audit_entries schema mismatch; run an explicit database migration"
            )
        role_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(audit_roles)")
        }
        if role_columns != {"guild_id", "role_id", "created_at_ms"}:
            connection.close()
            raise RuntimeError("audit_roles schema mismatch")
        staging_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(staging_entries)")
        }
        if staging_columns != {
            "staging_id", "guild_id", "entry_id", "payload_json", "received_at_ms"
        }:
            connection.close()
            raise RuntimeError("staging_entries schema mismatch")
        dead_letter_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(audit_dead_letters)")
        }
        if dead_letter_columns != {
            "guild_id", "entry_id", "source", "error_type", "error_text",
            "first_seen_at_ms", "last_seen_at_ms", "attempts",
        }:
            connection.close()
            raise RuntimeError("audit_dead_letters schema mismatch")
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        connection.commit()
        self._connection = connection

    async def upsert(
        self,
        rows: Iterable[AuditRow],
        *,
        checkpoint: Optional[tuple[int, int]] = None,
        dead_letters: Iterable[DeadLetter] = (),
    ) -> None:
        materialised = list(rows)
        materialised_dead_letters = list(dead_letters)
        if not materialised and not materialised_dead_letters and checkpoint is None:
            return
        await self._run(
            self._upsert,
            materialised,
            checkpoint,
            materialised_dead_letters,
        )

    def _upsert(
        self,
        rows: list[AuditRow],
        checkpoint: Optional[tuple[int, int]],
        dead_letters: list[DeadLetter],
    ) -> None:
        assert self._connection is not None
        with self._connection:
            if rows:
                self._connection.executemany(UPSERT_SQL, [row.values() for row in rows])
                resolved = [
                    (row.guild_id, row.entry_id)
                    for row in rows
                    if row.last_source in {"rest_backfill", "rest_refresh"}
                ]
                if resolved:
                    self._connection.executemany(
                        """
                        DELETE FROM audit_dead_letters
                        WHERE guild_id = ? AND entry_id = ?
                        """,
                        resolved,
                    )
            if dead_letters:
                self._connection.executemany(
                    DEAD_LETTER_UPSERT_SQL,
                    [dead_letter.values() for dead_letter in dead_letters],
                )
            if checkpoint is not None:
                guild_id, entry_id = checkpoint
                self._connection.execute(
                    """
                    INSERT INTO sync_state(guild_id, last_backfill_entry_id, updated_at_ms)
                    VALUES (?, ?, ?)
                    ON CONFLICT(guild_id) DO UPDATE SET
                        last_backfill_entry_id = MAX(
                            sync_state.last_backfill_entry_id,
                            excluded.last_backfill_entry_id
                        ),
                        updated_at_ms = excluded.updated_at_ms
                    """,
                    (guild_id, entry_id, now_ms()),
                )

    async def stage(self, rows: Iterable[AuditRow]) -> None:
        materialised = list(rows)
        if materialised:
            await self._run(self._stage, materialised)

    def _stage(self, rows: list[AuditRow]) -> None:
        assert self._connection is not None
        with self._connection:
            self._connection.executemany(
                """
                INSERT INTO staging_entries(
                    guild_id, entry_id, payload_json, received_at_ms
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        row.guild_id,
                        row.entry_id,
                        row.payload_json,
                        row.first_received_at_ms,
                    )
                    for row in rows
                ],
            )

    async def pop_staging(self, limit: int = STAGING_CONSUME_SIZE) -> StagingConsumeResult:
        return await self._run(self._pop_staging, limit)

    def _pop_staging(self, limit: int) -> StagingConsumeResult:
        assert self._connection is not None
        if limit < 1:
            raise ValueError("staging consume limit must be positive")
        invalid_count = 0
        invalid_by_guild: dict[int, int] = {}
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            staged = self._connection.execute(
                """
                SELECT staging_id, guild_id, entry_id, payload_json, received_at_ms
                FROM staging_entries
                ORDER BY staging_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            if not staged:
                return StagingConsumeResult(0, 0, ())

            rows: list[AuditRow] = []
            for _, guild_id, entry_id, payload_json, received_at_ms in staged:
                try:
                    rows.append(
                        staged_payload_to_row(
                            int(guild_id),
                            int(entry_id),
                            str(payload_json),
                            int(received_at_ms),
                        )
                    )
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                    OverflowError,
                    RecursionError,
                    sqlite3.InterfaceError,
                    json.JSONDecodeError,
                ):
                    invalid_count += 1
                    try:
                        invalid_guild_id = checked_sqlite_int(
                            guild_id, "staging.guild_id"
                        )
                    except (TypeError, ValueError, OverflowError):
                        invalid_guild_id = 0
                    invalid_by_guild[invalid_guild_id] = (
                        invalid_by_guild.get(invalid_guild_id, 0) + 1
                    )

            if rows:
                self._connection.executemany(
                    UPSERT_SQL, [row.values() for row in rows]
                )
            self._connection.executemany(
                "DELETE FROM staging_entries WHERE staging_id = ?",
                [(int(staged_id),) for staged_id, *_ in staged],
            )

        return StagingConsumeResult(
            consumed_count=len(staged),
            invalid_count=invalid_count,
            invalid_by_guild=tuple(sorted(invalid_by_guild.items())),
        )

    async def count_staging(self) -> int:
        return int(await self._run(self._count_staging))

    def _count_staging(self) -> int:
        assert self._connection is not None
        row = self._connection.execute(
            "SELECT COUNT(*) FROM staging_entries"
        ).fetchone()
        return int(row[0])

    async def count_dead_letters(self, guild_id: int) -> int:
        return int(await self._run(self._count_dead_letters, guild_id))

    def _count_dead_letters(self, guild_id: int) -> int:
        assert self._connection is not None
        row = self._connection.execute(
            "SELECT COUNT(*) FROM audit_dead_letters WHERE guild_id = ?",
            (guild_id,),
        ).fetchone()
        return int(row[0])

    async def checkpoint(self, guild_id: int) -> int:
        return int(await self._run(self._checkpoint, guild_id))

    def _checkpoint(self, guild_id: int) -> int:
        assert self._connection is not None
        row = self._connection.execute(
            "SELECT last_backfill_entry_id FROM sync_state WHERE guild_id = ?",
            (guild_id,),
        ).fetchone()
        return 0 if row is None else int(row[0])

    async def reset_checkpoint(self, guild_id: int) -> None:
        await self._run(self._reset_checkpoint, guild_id)

    def _reset_checkpoint(self, guild_id: int) -> None:
        assert self._connection is not None
        with self._connection:
            self._connection.execute(
                "DELETE FROM sync_state WHERE guild_id = ?", (guild_id,)
            )

    async def add_role(self, guild_id: int, role_id: int) -> bool:
        return bool(await self._run(self._add_role, guild_id, role_id))

    def _add_role(self, guild_id: int, role_id: int) -> bool:
        assert self._connection is not None
        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO audit_roles(guild_id, role_id, created_at_ms)
                VALUES (?, ?, ?)
                """,
                (guild_id, role_id, now_ms()),
            )
        return cursor.rowcount > 0

    async def remove_role(self, guild_id: int, role_id: int) -> bool:
        return bool(await self._run(self._remove_role, guild_id, role_id))

    def _remove_role(self, guild_id: int, role_id: int) -> bool:
        assert self._connection is not None
        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM audit_roles WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id),
            )
        return cursor.rowcount > 0

    async def clear_roles(self, guild_id: int) -> int:
        return int(await self._run(self._clear_roles, guild_id))

    def _clear_roles(self, guild_id: int) -> int:
        assert self._connection is not None
        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM audit_roles WHERE guild_id = ?", (guild_id,)
            )
        return cursor.rowcount

    async def list_roles(self, guild_id: int) -> list[int]:
        return list(await self._run(self._list_roles, guild_id))

    def _list_roles(self, guild_id: int) -> list[int]:
        assert self._connection is not None
        rows = self._connection.execute(
            """
            SELECT role_id FROM audit_roles
            WHERE guild_id = ? ORDER BY role_id
            """,
            (guild_id,),
        ).fetchall()
        return [int(row[0]) for row in rows]

    async def export_count(self, query: AuditExportQuery) -> int:
        return int(await self._run(self._export_count, query))

    def _export_count(self, query: AuditExportQuery) -> int:
        assert self._connection is not None
        clauses, parameters = self._export_conditions(query)
        row = self._connection.execute(
            f"SELECT COUNT(*) FROM audit_entries WHERE {' AND '.join(clauses)}",
            parameters,
        ).fetchone()
        return int(row[0])

    async def export_fetch_batch(
        self,
        query: AuditExportQuery,
        last_entry_id: Optional[int],
        batch_size: int = EXPORT_BATCH_SIZE,
    ) -> list[dict[str, Any]]:
        return list(
            await self._run(
                self._export_fetch_batch,
                query,
                last_entry_id,
                batch_size,
            )
        )

    def _export_fetch_batch(
        self,
        query: AuditExportQuery,
        last_entry_id: Optional[int],
        batch_size: int,
    ) -> list[dict[str, Any]]:
        assert self._connection is not None
        if not 1 <= batch_size <= 10_000:
            raise ValueError("export batch_size must be between 1 and 10000")
        clauses, parameters = self._export_conditions(query)
        if last_entry_id is not None:
            clauses.append("entry_id > ?")
            parameters.append(last_entry_id)
        parameters.append(batch_size)
        rows = self._connection.execute(
            f"""
            SELECT entry_id, action_type, user_id, target_id,
                   created_at_ms, reason, payload_json, last_source
            FROM audit_entries
            WHERE {' AND '.join(clauses)}
            ORDER BY entry_id ASC
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        return [
            {
                "entry_id": int(row[0]),
                "action_type": int(row[1]),
                "user_id": None if row[2] is None else int(row[2]),
                "target_id": None if row[3] is None else int(row[3]),
                "created_at_ms": int(row[4]),
                "reason": row[5],
                "payload_json": row[6],
                "last_source": row[7],
            }
            for row in rows
        ]

    @staticmethod
    def _export_conditions(
        query: AuditExportQuery,
    ) -> tuple[list[str], list[Any]]:
        clauses = ["guild_id = ?"]
        parameters: list[Any] = [query.guild_id]
        optional_conditions = (
            ("action_type = ?", query.action_type),
            ("entry_id >= ?", query.lower_entry_id),
            ("entry_id <= ?", query.upper_entry_id),
            ("user_id = ?", query.user_id),
            ("target_id = ?", query.target_id),
        )
        for clause, value in optional_conditions:
            if value is not None:
                clauses.append(clause)
                parameters.append(value)
        return clauses, parameters

    async def query_entries(self, query: AuditQuery) -> list[dict[str, Any]]:
        return list(await self._run(self._query_entries, query))

    def _query_entries(self, query: AuditQuery) -> list[dict[str, Any]]:
        assert self._connection is not None
        if query.filter_column not in {"user_id", "target_id"}:
            raise ValueError("Invalid audit filter column")

        clauses = ["guild_id = ?", f"{query.filter_column} = ?"]
        parameters: list[Any] = [query.guild_id, query.subject_id]
        if query.action_type is not None:
            clauses.append("action_type = ?")
            parameters.append(query.action_type)
        if query.lower_entry_id is not None:
            clauses.append("entry_id >= ?")
            parameters.append(query.lower_entry_id)
        if query.upper_entry_id is not None:
            clauses.append("entry_id <= ?")
            parameters.append(query.upper_entry_id)
        if query.cursor is not None:
            clauses.append("entry_id < ?")
            parameters.append(query.cursor)

        parameters.append(query.page_size + 1)
        sql = f"""
            SELECT guild_id, entry_id, action_type, user_id, target_id,
                   created_at_ms, reason, payload_json, last_source
            FROM audit_entries
            WHERE {' AND '.join(clauses)}
            ORDER BY entry_id DESC
            LIMIT ?
        """
        rows = self._connection.execute(sql, parameters).fetchall()
        return [
            {
                "guild_id": int(row[0]),
                "entry_id": int(row[1]),
                "action_type": int(row[2]),
                "user_id": None if row[3] is None else int(row[3]),
                "target_id": None if row[4] is None else int(row[4]),
                "created_at_ms": int(row[5]),
                "reason": row[6],
                "payload_json": row[7],
                "last_source": row[8],
            }
            for row in rows
        ]

    async def guild_stats(self, guild_id: int) -> dict[str, Any]:
        return dict(await self._run(self._guild_stats, guild_id))

    def _guild_stats(self, guild_id: int) -> dict[str, Any]:
        assert self._connection is not None
        aggregate = self._connection.execute(
            """
            SELECT COUNT(*), MIN(entry_id), MAX(entry_id),
                   MIN(created_at_ms), MAX(created_at_ms)
            FROM audit_entries WHERE guild_id = ?
            """,
            (guild_id,),
        ).fetchone()
        state = self._connection.execute(
            """
            SELECT last_backfill_entry_id, updated_at_ms
            FROM sync_state WHERE guild_id = ?
            """,
            (guild_id,),
        ).fetchone()
        return {
            "count": int(aggregate[0]),
            "min_entry_id": aggregate[1],
            "max_entry_id": aggregate[2],
            "min_created_at_ms": aggregate[3],
            "max_created_at_ms": aggregate[4],
            "checkpoint": None if state is None else int(state[0]),
            "checkpoint_updated_at_ms": None if state is None else int(state[1]),
        }

    async def prune_before(
        self,
        cutoff_ms: int,
        guild_ids: Iterable[int],
        *,
        batch_size: int = RETENTION_PRUNE_BATCH_SIZE,
    ) -> tuple[int, int]:
        cutoff_entry_id = max(0, (cutoff_ms - DISCORD_EPOCH_MS) << 22)
        if cutoff_entry_id == 0:
            return 0, 0
        stored_guild_ids = await self._run(self._retention_guild_ids)
        all_guild_ids = sorted({int(value) for value in guild_ids} | set(stored_guild_ids))
        pruned_entries = 0
        pruned_dead_letters = 0
        for guild_id in all_guild_ids:
            while True:
                deleted = int(
                    await self._run(
                        self._prune_entries_batch,
                        guild_id,
                        cutoff_entry_id,
                        cutoff_ms,
                        batch_size,
                    )
                )
                pruned_entries += deleted
                if deleted < batch_size:
                    break
                await asyncio.sleep(0)
            while True:
                deleted = int(
                    await self._run(
                        self._prune_dead_letters_batch,
                        guild_id,
                        cutoff_entry_id,
                        batch_size,
                    )
                )
                pruned_dead_letters += deleted
                if deleted < batch_size:
                    break
                await asyncio.sleep(0)
        return pruned_entries, pruned_dead_letters

    def _retention_guild_ids(self) -> list[int]:
        assert self._connection is not None
        rows = self._connection.execute(
            """
            SELECT guild_id FROM sync_state
            UNION
            SELECT guild_id FROM audit_roles
            UNION
            SELECT guild_id FROM audit_dead_letters
            ORDER BY guild_id
            """
        ).fetchall()
        guild_ids = {int(row[0]) for row in rows}
        last_guild_id = -(2**63)
        while True:
            row = self._connection.execute(
                """
                SELECT guild_id FROM audit_entries
                WHERE guild_id > ? ORDER BY guild_id LIMIT 1
                """,
                (last_guild_id,),
            ).fetchone()
            if row is None:
                break
            last_guild_id = int(row[0])
            guild_ids.add(last_guild_id)
        return sorted(guild_ids)

    def _prune_entries_batch(
        self,
        guild_id: int,
        cutoff_entry_id: int,
        cutoff_ms: int,
        batch_size: int,
    ) -> int:
        assert self._connection is not None
        with self._connection:
            cursor = self._connection.execute(
                """
                DELETE FROM audit_entries
                WHERE guild_id = ? AND entry_id IN (
                    SELECT entry_id FROM audit_entries
                    WHERE guild_id = ? AND entry_id < ? AND created_at_ms < ?
                    ORDER BY entry_id ASC LIMIT ?
                )
                """,
                (guild_id, guild_id, cutoff_entry_id, cutoff_ms, batch_size),
            )
        return cursor.rowcount

    def _prune_dead_letters_batch(
        self,
        guild_id: int,
        cutoff_entry_id: int,
        batch_size: int,
    ) -> int:
        assert self._connection is not None
        with self._connection:
            cursor = self._connection.execute(
                """
                DELETE FROM audit_dead_letters
                WHERE guild_id = ? AND (entry_id, source) IN (
                    SELECT entry_id, source FROM audit_dead_letters
                    WHERE guild_id = ? AND entry_id < ?
                    ORDER BY entry_id ASC, source ASC LIMIT ?
                )
                """,
                (guild_id, guild_id, cutoff_entry_id, batch_size),
            )
        return cursor.rowcount

    async def vacuum(self) -> None:
        await self._run(self._vacuum)

    def _vacuum(self) -> None:
        assert self._connection is not None
        self._connection.execute("VACUUM")

    async def checkpoint_wal(self) -> tuple[int, int, int]:
        return tuple(await self._run(self._checkpoint_wal))

    def _checkpoint_wal(self) -> tuple[int, int, int]:
        assert self._connection is not None
        row = self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return int(row[0]), int(row[1]), int(row[2])

    async def close(self) -> None:
        await self._run(self._close)
        self._executor.shutdown(wait=True)

    def _close(self) -> None:
        if self._connection is not None:
            self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._connection.close()
            self._connection = None


class AuditInputError(app_commands.AppCommandError):
    pass


SNOWFLAKE_PATTERN = re.compile(r"^[0-9]{1,20}$")
SQLITE_INT_MAX = 2**63 - 1
ACTION_NAMES = {int(action.value): action.name for action in discord.AuditLogAction}
ACTION_NAMES_ZH = {
    "guild_update": "服务器更新",
    "channel_create": "新建频道",
    "channel_update": "频道更新",
    "channel_delete": "删除频道",
    "overwrite_create": "新建频道权限",
    "overwrite_update": "修改频道权限",
    "overwrite_delete": "删除频道权限",
    "kick": "踢出成员",
    "member_prune": "清理不活跃成员",
    "ban": "封禁成员",
    "unban": "解除封禁",
    "member_update": "更新成员信息",
    "member_role_update": "更新成员身份组",
    "member_move": "移动语音成员",
    "member_disconnect": "断开语音成员",
    "bot_add": "添加机器人",
    "role_create": "新建身份组",
    "role_update": "修改身份组",
    "role_delete": "删除身份组",
    "invite_create": "新建邀请链接",
    "invite_update": "修改邀请链接",
    "invite_delete": "删除邀请链接",
    "webhook_create": "新建网络回调",
    "webhook_update": "修改网络回调",
    "webhook_delete": "删除网络回调",
    "emoji_create": "新建表情",
    "emoji_update": "修改表情",
    "emoji_delete": "删除表情",
    "message_delete": "删除消息",
    "message_bulk_delete": "批量删除消息",
    "message_pin": "置顶消息",
    "message_unpin": "取消置顶消息",
    "integration_create": "新建集成",
    "integration_update": "修改集成",
    "integration_delete": "删除集成",
    "stage_instance_create": "新建舞台实例",
    "stage_instance_update": "修改舞台实例",
    "stage_instance_delete": "删除舞台实例",
    "sticker_create": "新建贴纸",
    "sticker_update": "修改贴纸",
    "sticker_delete": "删除贴纸",
    "scheduled_event_create": "新建日程事件",
    "scheduled_event_update": "修改日程事件",
    "scheduled_event_delete": "删除日程事件",
    "thread_create": "新建子区",
    "thread_update": "子区更新",
    "thread_delete": "删除子区",
    "app_command_permission_update": "更新应用命令权限",
    "soundboard_sound_create": "新建音效板音效",
    "soundboard_sound_update": "修改音效板音效",
    "soundboard_sound_delete": "删除音效板音效",
    "automod_rule_create": "新建自动审核规则",
    "automod_rule_update": "修改自动审核规则",
    "automod_rule_delete": "删除自动审核规则",
    "automod_block_message": "自动审核拦截消息",
    "automod_flag_message": "自动审核标记消息到频道",
    "automod_timeout_member": "自动审核禁用用户通信",
    "automod_quarantine_user": "自动审核隔离用户",
    "creator_monetization_request_created": "新建创作者变现申请",
    "creator_monetization_terms_accepted": "接受创作者变现条款",
    "onboarding_prompt_create": "新建新成员引导问题",
    "onboarding_prompt_update": "修改新成员引导问题",
    "onboarding_prompt_delete": "删除新成员引导问题",
    "onboarding_create": "新建新成员引导",
    "onboarding_update": "修改新成员引导",
    "home_settings_create": "新建服务器主页设置",
    "home_settings_update": "修改服务器主页设置",
}


BEIJING_TZ = dt.timezone(dt.timedelta(hours=8))


def parse_time_bound(value: Optional[str], label: str) -> Optional[dt.datetime]:
    if value is None or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=BEIJING_TZ)
        return parsed.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise AuditInputError(
            f"参数 {label} 请直接写日期时间，例如 2026-08-17 15:30（默认北京时间）"
        ) from exc


def resolve_subject_id(
    user: Optional[discord.User], user_id: Optional[str]
) -> int:
    if user is not None and user_id:
        raise AuditInputError("user 与 user_id 不能同时填写。")
    if user is not None:
        return user.id
    if user_id and SNOWFLAKE_PATTERN.fullmatch(user_id.strip()):
        value = int(user_id)
        if 0 < value <= 9_223_372_036_854_775_807:
            return value
    raise AuditInputError("请提供用户或有效的 Discord 用户 ID。")


def parse_optional_snowflake(value: Optional[str], label: str) -> Optional[int]:
    if value is None or not value.strip():
        return None
    text = value.strip()
    if SNOWFLAKE_PATTERN.fullmatch(text):
        snowflake = int(text)
        if 0 < snowflake <= SQLITE_INT_MAX:
            return snowflake
    raise AuditInputError(f"{label} 必须是有效的 Discord ID。")


def checked_time_snowflake(value: dt.datetime, label: str) -> int:
    try:
        snowflake = discord.utils.time_snowflake(value, high=False)
    except (ValueError, OverflowError) as exc:
        raise AuditInputError(f"参数 {label} 超出支持的时间范围。") from exc
    if not 0 <= snowflake <= SQLITE_INT_MAX:
        raise AuditInputError(f"参数 {label} 超出归档 Snowflake 范围。")
    return snowflake


def make_time_bounds(
    after: Optional[str], before: Optional[str]
) -> tuple[Optional[int], Optional[int]]:
    after_time = parse_time_bound(after, "after")
    before_time = parse_time_bound(before, "before")
    if after_time and before_time and after_time >= before_time:
        raise AuditInputError("after 必须早于 before。")
    lower = (
        None if after_time is None else checked_time_snowflake(after_time, "after")
    )
    upper = (
        None
        if before_time is None
        else checked_time_snowflake(before_time, "before") - 1
    )
    if upper is not None and not 0 <= upper <= SQLITE_INT_MAX:
        raise AuditInputError("before 超出归档 Snowflake 范围。")
    return lower, upper


def clean_text(value: Any, limit: int) -> str:
    text = discord.utils.escape_markdown(str(value), as_needed=True)
    text = text.replace("\x00", "").replace("`", "ˋ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def action_label(action_type: int, payload: dict[str, Any]) -> str:
    name = payload.get("action_name") or ACTION_NAMES.get(action_type)
    zh = ACTION_NAMES_ZH.get(name, name) if name else None
    return f"{zh or '未知'} ({action_type})"


def parse_row_payload(row: dict[str, Any]) -> tuple[dict[str, Any], Optional[str]]:
    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, ValueError, RecursionError) as exc:
        return {}, f"payload_json 解析失败：{type(exc).__name__}"
    if not isinstance(payload, dict):
        return {}, "payload_json 顶层不是 JSON 对象"
    return payload, None


def export_csv_values(row: dict[str, Any]) -> tuple[Any, ...]:
    payload, _ = parse_row_payload(row)
    action_name = payload.get("action_name") or ACTION_NAMES.get(row["action_type"])
    if not isinstance(action_name, str):
        action_name = ACTION_NAMES.get(row["action_type"])
    action_name_zh = (
        ACTION_NAMES_ZH.get(action_name, action_name) if action_name else "未知"
    )
    created_at = dt.datetime.fromtimestamp(
        row["created_at_ms"] / 1000,
        dt.timezone.utc,
    ).strftime("%Y-%m-%d %H:%M:%S")
    return (
        row["entry_id"],
        created_at,
        action_name_zh,
        row["action_type"],
        "" if row["user_id"] is None else row["user_id"],
        "" if row["target_id"] is None else row["target_id"],
        "" if row["reason"] is None else row["reason"],
        row["last_source"],
        row["payload_json"],
    )


def encoded_csv_record(values: Iterable[Any], *, bom: bool = False) -> bytes:
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\r\n").writerow(values)
    text = stream.getvalue()
    if bom:
        text = "\ufeff" + text
    return text.encode("utf-8")


class ExportCsvWriter:
    def __init__(self, directory: Path, guild_id: int) -> None:
        self.directory = directory
        self.guild_id = guild_id
        self.part_number = 0
        self.current_path: Optional[Path] = None
        self.current_rows = 0
        self.current_bytes = 0
        self.header = encoded_csv_record(EXPORT_CSV_HEADER, bom=True)

    def _start_part(self) -> None:
        self.part_number += 1
        self.current_path = self.directory / (
            f"audit_export_{self.guild_id}_part_{self.part_number:03d}.csv"
        )
        self.current_path.write_bytes(self.header)
        self.current_rows = 0
        self.current_bytes = len(self.header)

    def append_rows(self, rows: Sequence[dict[str, Any]]) -> list[Path]:
        completed: list[Path] = []
        output: Optional[Any] = None
        try:
            for row in rows:
                record = encoded_csv_record(export_csv_values(row))
                if len(self.header) + len(record) > EXPORT_PART_MAX_BYTES:
                    raise ValueError(
                        f"audit entry {row['entry_id']} exceeds the CSV part size limit"
                    )
                if self.current_path is None:
                    self._start_part()
                if self.current_rows and (
                    self.current_rows >= EXPORT_PART_MAX_ROWS
                    or self.current_bytes + len(record) > EXPORT_PART_MAX_BYTES
                ):
                    if output is not None:
                        output.close()
                        output = None
                    assert self.current_path is not None
                    completed.append(self.current_path)
                    self._start_part()
                if output is None:
                    assert self.current_path is not None
                    output = self.current_path.open("ab")
                output.write(record)
                self.current_rows += 1
                self.current_bytes += len(record)
        finally:
            if output is not None:
                output.close()
        return completed

    def finish(self) -> list[Path]:
        if self.current_path is None or self.current_rows == 0:
            return []
        completed = [self.current_path]
        self.current_path = None
        self.current_rows = 0
        self.current_bytes = 0
        return completed


def zip_export_csv(csv_path: Path) -> Path:
    zip_path = csv_path.with_suffix(".zip")
    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as archive:
        archive.write(csv_path, arcname=csv_path.name)
    return zip_path


def row_field(row: dict[str, Any]) -> tuple[str, str]:
    payload, _ = parse_row_payload(row)
    action = action_label(row["action_type"], payload)
    timestamp = row["created_at_ms"] // 1000
    actor = "—" if row["user_id"] is None else f"`{row['user_id']}`"
    target = "—" if row["target_id"] is None else f"`{row['target_id']}`"
    reason = clean_text(row["reason"] or "—", 60)
    name = clean_text(f"{action} · {row['entry_id']}", 256)
    value = (
        f"**时间：** <t:{timestamp}:f>\n"
        f"**操作者：** {actor}\n"
        f"**目标：** {target}\n"
        f"**理由：** {reason}\n"
        f"**来源：** `{row['last_source']}`\n"
        f"**详情：** *💡 完整数据请通过下方下拉列表选取查看*"
    )
    return name, value


DETAIL_JSON_CHUNK_SIZE = 700
DETAIL_JSON_MAX_CHUNKS = 5


def discord_text_units(text: str) -> int:
    return sum(2 if ord(character) > 0xFFFF else 1 for character in text)


def split_discord_text(text: str, maximum_units: int) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_units = 0
    for character in text:
        units = 2 if ord(character) > 0xFFFF else 1
        if current and current_units + units > maximum_units:
            chunks.append("".join(current))
            current = []
            current_units = 0
        current.append(character)
        current_units += units
    if current:
        chunks.append("".join(current))
    return chunks


def clipped_discord_text(text: str, maximum_units: int, marker: str) -> str:
    if discord_text_units(text) <= maximum_units:
        return text
    marker_units = discord_text_units(marker)
    available = max(0, maximum_units - marker_units)
    prefix = split_discord_text(text, available)[0] if available else ""
    return prefix + marker


def select_option_text(value: Any, limit: int = 100) -> str:
    text = " ".join(str(value).replace("\x00", "").split())
    if not text:
        text = "未知"
    return clipped_discord_text(text, limit, "…")


def formatted_detail_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=str,
    ).replace("`", "ˋ")


def clipped_detail_json(value: Any) -> tuple[str, bool]:
    text = formatted_detail_json(value)
    if discord_text_units(text) <= DETAIL_JSON_CHUNK_SIZE:
        return text, False
    marker = "\n…（此分组内容过长，已截断）"
    return clipped_discord_text(text, DETAIL_JSON_CHUNK_SIZE, marker), True


def detail_json_fields(
    document: dict[str, Any],
    payload: dict[str, Any],
) -> tuple[list[tuple[str, str]], bool]:
    text = formatted_detail_json(document)
    maximum = DETAIL_JSON_CHUNK_SIZE * DETAIL_JSON_MAX_CHUNKS
    if discord_text_units(text) <= maximum:
        chunks = split_discord_text(text, DETAIL_JSON_CHUNK_SIZE) or ["{}"]
        return [
            (f"完整数据 {index}/{len(chunks)}", chunk)
            for index, chunk in enumerate(chunks, start=1)
        ], False

    changes = payload.get("changes")
    if isinstance(changes, dict):
        before = changes.get("before")
        after = changes.get("after")
    else:
        before = changes
        after = None
    remaining_payload = {
        key: value
        for key, value in payload.items()
        if key not in {"target", "changes", "options"}
    }
    groups = (
        ("目标对象", payload.get("target")),
        ("变更前", before),
        ("变更后", after),
        ("选项", payload.get("options")),
        (
            "其他载荷与归档信息",
            {
                "archive": document.get("archive"),
                "payload": remaining_payload,
            },
        ),
    )
    fields: list[tuple[str, str]] = []
    truncated = False
    for name, value in groups:
        content, group_truncated = clipped_detail_json(value)
        truncated = truncated or group_truncated
        fields.append((name, content))
    return fields, truncated


async def audit_authorized_check(interaction: discord.Interaction) -> bool:
    client = interaction.client
    checker = getattr(client, "is_audit_authorized", None)
    return bool(checker and await checker(interaction))


async def guild_owner_check(interaction: discord.Interaction) -> bool:
    guild = interaction.guild
    if guild is None:
        return False
    if guild.owner_id == interaction.user.id:
        return True

    # Management access is granted to the server owner or an Administrator.
    member = guild.get_member(interaction.user.id)
    if member is None and isinstance(interaction.user, discord.Member):
        member = interaction.user
    return bool(member and member.guild_permissions.administrator)


def audit_authorized() -> Any:
    return app_commands.check(audit_authorized_check)


def guild_owner_only() -> Any:
    return app_commands.check(guild_owner_check)


async def audit_action_autocomplete(
    interaction: discord.Interaction, current: int | str
) -> list[app_commands.Choice[int]]:
    needle = str(current).casefold().strip()
    choices: list[app_commands.Choice[int]] = []

    if needle.isdigit():
        target = int(needle)
        exact = [value for value in ACTION_NAMES if value == target]
        for value in exact:
            name = ACTION_NAMES[value]
            zh = ACTION_NAMES_ZH.get(name, name)
            choices.append(
                app_commands.Choice(
                    name=f"操作类型 {value}：{zh}"[:100],
                    value=value,
                )
            )
        if choices:
            return choices

    for value, name in ACTION_NAMES.items():
        zh = ACTION_NAMES_ZH.get(name, name)
        haystack = f"{value} {zh} {name}".casefold()
        if needle and needle not in haystack:
            continue
        choices.append(
            app_commands.Choice(
                name=f"操作类型 {value}：{zh}"[:100],
                value=value,
            )
        )
        if len(choices) >= 25:
            break
    return choices


class AuditEntrySelect(discord.ui.Select["AuditPageView"]):
    def __init__(self) -> None:
        super().__init__(
            placeholder="选择当前页的审核日志查看完整详情",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(
                    label="当前页没有可选条目",
                    value="0",
                )
            ],
            row=0,
            disabled=True,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer()
        view = self.view
        if view is None:
            return
        async with view.navigation_lock:
            try:
                entry_id = int(self.values[0])
            except (IndexError, ValueError):
                return
            row = next(
                (
                    candidate
                    for candidate in view.visible_rows
                    if candidate["entry_id"] == entry_id
                ),
                None,
            )
            if row is None:
                await interaction.followup.send(
                    "该条目已不在当前页，请重新选择。",
                    ephemeral=True,
                )
                return
            view.detail_row = row
            await interaction.edit_original_response(
                embed=await view.build_embed(refresh_rows=False),
                view=view,
            )


class AuditPageView(discord.ui.View):
    def __init__(
        self,
        client: "AuditArchiver",
        requester_id: int,
        query: AuditQuery,
        title: str,
    ) -> None:
        super().__init__(timeout=180.0)
        self.client = client
        self.requester_id = requester_id
        self.query = query
        self.title = title
        self.cursors: list[Optional[int]] = [query.cursor]
        self.position = 0
        self.visible_rows: list[dict[str, Any]] = []
        self.has_more = False
        self.detail_row: Optional[dict[str, Any]] = None
        self.navigation_lock = asyncio.Lock()
        self.message: Optional[discord.InteractionMessage] = None
        self.entry_select = AuditEntrySelect()
        self.add_item(self.entry_select)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message(
                "此分页会话属于其他用户。", ephemeral=True
            )
            return False
        if not await self.client.is_audit_authorized(interaction):
            await interaction.response.send_message(
                "你的审核日志查询权限已失效。", ephemeral=True
            )
            return False
        return True

    def update_controls(self) -> None:
        self.previous_button.disabled = self.position == 0
        self.next_button.disabled = not self.has_more
        self.return_button.disabled = self.detail_row is None

        options: list[discord.SelectOption] = []
        selected_entry_id = (
            None if self.detail_row is None else self.detail_row["entry_id"]
        )
        for row in self.visible_rows:
            payload, _ = parse_row_payload(row)
            action = action_label(row["action_type"], payload)
            timestamp = row["created_at_ms"] // 1000
            actor = "无" if row["user_id"] is None else str(row["user_id"])
            target = "无" if row["target_id"] is None else str(row["target_id"])
            options.append(
                discord.SelectOption(
                    label=select_option_text(
                        f"{action} · #{row['entry_id']}"
                    ),
                    value=str(row["entry_id"]),
                    description=select_option_text(
                        f"{dt.datetime.fromtimestamp(timestamp, dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC · 操作者 {actor} · 目标 {target}"
                    ),
                    default=row["entry_id"] == selected_entry_id,
                )
            )

        self.entry_select.options = options or [
            discord.SelectOption(label="当前页没有可选条目", value="0")
        ]
        self.entry_select.disabled = not options
        self.entry_select.placeholder = (
            "已选择当前审核日志"
            if self.detail_row is not None
            else "选择当前页的审核日志查看完整详情"
        )

    async def build_embed(self, *, refresh_rows: bool = True) -> discord.Embed:
        if refresh_rows:
            current = replace(self.query, cursor=self.cursors[self.position])
            rows = await self.client.store.query_entries(current)
            self.has_more = len(rows) > current.page_size
            self.visible_rows = rows[: current.page_size]
            if self.detail_row is not None and not any(
                row["entry_id"] == self.detail_row["entry_id"]
                for row in self.visible_rows
            ):
                self.detail_row = None

        self.update_controls()
        if self.detail_row is not None:
            return self.build_detail_embed(self.detail_row)
        return self.build_list_embed()

    def build_list_embed(self) -> discord.Embed:
        embed = discord.Embed(
            title=self.title,
            colour=discord.Colour.blurple(),
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        if not self.visible_rows:
            embed.description = "没有匹配的已归档审核日志。"
        else:
            for row in self.visible_rows:
                name, value = row_field(row)
                embed.add_field(name=name, value=value, inline=False)
        cursor = self.cursors[self.position]
        embed.set_footer(
            text=f"第 {self.position + 1} 页 · 游标 {cursor or '最新'}"
        )
        return embed

    def build_detail_embed(self, row: dict[str, Any]) -> discord.Embed:
        payload, payload_error = parse_row_payload(row)
        action = action_label(row["action_type"], payload)
        timestamp = row["created_at_ms"] // 1000
        actor = "无" if row["user_id"] is None else str(row["user_id"])
        target_id = "无" if row["target_id"] is None else str(row["target_id"])
        reason = row["reason"] if row["reason"] is not None else payload.get("reason")
        reason_text = clean_text(reason if reason is not None else "无", 600)
        description = (
            f"**操作类型：** {clean_text(action, 100)}\n"
            f"**条目 ID：** `{row['entry_id']}`\n"
            f"**时间：** <t:{timestamp}:F>\n"
            f"**操作者 ID：** `{actor}`\n"
            f"**目标 ID：** `{target_id}`\n"
            f"**理由：** {reason_text}\n"
            f"**来源：** `{clean_text(row['last_source'], 80)}`"
        )
        if payload_error is not None:
            description += f"\n**载荷状态：** {payload_error}"

        complete_document = {
            "archive": {
                "action_name": (
                    payload.get("action_name")
                    or ACTION_NAMES.get(row["action_type"])
                ),
                "action_type": row["action_type"],
                "entry_id": row["entry_id"],
                "created_at_ms": row["created_at_ms"],
                "user_id": row["user_id"],
                "target_id": row["target_id"],
                "reason": reason,
                "source": row["last_source"],
            },
            "payload": payload,
        }
        detail_fields, truncated = detail_json_fields(
            complete_document,
            payload,
        )
        embed = discord.Embed(
            title=f"审核日志详情 · {row['entry_id']}",
            description=description,
            colour=discord.Colour.gold(),
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        for name, content in detail_fields:
            embed.add_field(
                name=name,
                value=f"```json\n{content}\n```",
                inline=False,
            )
        footer = f"第 {self.position + 1} 页 · 详情模式"
        if truncated:
            footer += " · 内容已截断"
        embed.set_footer(text=footer)
        return embed

    @discord.ui.button(
        label="返回列表",
        style=discord.ButtonStyle.secondary,
        row=1,
        disabled=True,
    )
    async def return_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        await interaction.response.defer()
        async with self.navigation_lock:
            self.detail_row = None
            await interaction.edit_original_response(
                embed=await self.build_embed(refresh_rows=False),
                view=self,
            )

    @discord.ui.button(
        label="上一页",
        style=discord.ButtonStyle.secondary,
        row=1,
    )
    async def previous_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        await interaction.response.defer()
        async with self.navigation_lock:
            if self.position > 0:
                self.position -= 1
            self.detail_row = None
            await interaction.edit_original_response(
                embed=await self.build_embed(), view=self
            )

    @discord.ui.button(
        label="下一页",
        style=discord.ButtonStyle.primary,
        row=1,
    )
    async def next_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        await interaction.response.defer()
        async with self.navigation_lock:
            if not self.visible_rows or not self.has_more:
                return
            next_cursor = self.visible_rows[-1]["entry_id"]
            if self.position + 1 < len(self.cursors):
                self.cursors[self.position + 1] = next_cursor
            else:
                self.cursors.append(next_cursor)
            self.position += 1
            self.detail_row = None
            await interaction.edit_original_response(
                embed=await self.build_embed(), view=self
            )

    async def on_timeout(self) -> None:
        for item in self.children:
            if isinstance(item, (discord.ui.Button, discord.ui.Select)):
                item.disabled = True
        if self.message is not None:
            with contextlib.suppress(discord.HTTPException):
                await self.message.edit(view=self)

    async def on_error(
        self,
        interaction: discord.Interaction,
        error: Exception,
        item: discord.ui.Item[Any],
        /,
    ) -> None:
        LOG.error(
            "Audit pagination failed for item %r",
            item,
            exc_info=(type(error), error, error.__traceback__),
        )
        message = "审核日志分页失败，请联系管理员查看机器人日志。"
        with contextlib.suppress(discord.HTTPException):
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)


class AuditCommands(app_commands.Group):
    def __init__(self, client: "AuditArchiver") -> None:
        super().__init__(
            name="audit",
            description="检索并管理已归档的 Discord 审核日志",
            guild_only=True,
        )
        self.client = client

    async def send_query(
        self,
        interaction: discord.Interaction,
        *,
        filter_column: Literal["user_id", "target_id"],
        user: Optional[discord.User],
        user_id: Optional[str],
        action_type: Optional[int],
        after: Optional[str],
        before: Optional[str],
        page_size: int,
    ) -> None:
        if interaction.guild_id is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        if not 5 <= page_size <= 15:
            raise AuditInputError("page_size 必须在 5 到 15 之间。")
        if action_type is not None and action_type < 0:
            raise AuditInputError("action_type 必须是非负整数。")
        subject_id = resolve_subject_id(user, user_id)
        lower, upper = make_time_bounds(after, before)
        query = AuditQuery(
            guild_id=interaction.guild_id,
            filter_column=filter_column,
            subject_id=subject_id,
            action_type=action_type,
            lower_entry_id=lower,
            upper_entry_id=upper,
            page_size=page_size,
        )
        label = "操作者" if filter_column == "user_id" else "目标"
        title = f"审核日志查询 · {label} {subject_id}"
        view = AuditPageView(self.client, interaction.user.id, query, title)
        await interaction.response.defer(ephemeral=True, thinking=True)
        await interaction.edit_original_response(embed=await view.build_embed(), view=view)
        view.message = await interaction.original_response()

    @app_commands.command(name="by-actor", description="查询指定用户执行的审核操作")
    @app_commands.describe(
        user="选择当前服务器中的用户",
        user_id="手动填写用户 ID，适用于已离开服务器的用户",
        action_type="按操作类型筛选，可输入中文关键词或数字搜索，例如：封禁、身份组、子区、51",
        after="起始时间（含），例如 2026-08-17 15:30，默认北京时间",
        before="结束时间（不含），例如 2026-08-17 15:30，默认北京时间",
        page_size="每页结果数，范围 5–15",
    )
    @app_commands.autocomplete(action_type=audit_action_autocomplete)
    @audit_authorized()
    async def by_actor(
        self,
        interaction: discord.Interaction,
        user: Optional[discord.User] = None,
        user_id: Optional[str] = None,
        action_type: Optional[int] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        page_size: int = 10,
    ) -> None:
        await self.send_query(
            interaction,
            filter_column="user_id",
            user=user,
            user_id=user_id,
            action_type=action_type,
            after=after,
            before=before,
            page_size=page_size,
        )

    @app_commands.command(name="by-target", description="查询以指定用户为目标的审核操作")
    @app_commands.describe(
        user="选择当前服务器中的目标用户",
        user_id="手动填写目标用户 ID，适用于已离开服务器的用户",
        action_type="按操作类型筛选，可输入中文关键词或数字搜索，例如：封禁、身份组、子区、51",
        after="起始时间（含），例如 2026-08-17 15:30，默认北京时间",
        before="结束时间（不含），例如 2026-08-17 15:30，默认北京时间",
        page_size="每页结果数，范围 5–15",
    )
    @app_commands.autocomplete(action_type=audit_action_autocomplete)
    @audit_authorized()
    async def by_target(
        self,
        interaction: discord.Interaction,
        user: Optional[discord.User] = None,
        user_id: Optional[str] = None,
        action_type: Optional[int] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        page_size: int = 10,
    ) -> None:
        await self.send_query(
            interaction,
            filter_column="target_id",
            user=user,
            user_id=user_id,
            action_type=action_type,
            after=after,
            before=before,
            page_size=page_size,
        )

    @app_commands.command(name="export", description="导出归档审核日志为 CSV 文件")
    @app_commands.describe(
        after="起始时间（含），例如 2026-08-17 15:30，默认北京时间",
        before="结束时间（不含），例如 2026-08-17 15:30，默认北京时间",
        action_type="按操作类型筛选，可输入中文关键词或数字搜索",
        user_id="按操作者 ID 筛选",
        target_id="按目标 ID 筛选",
    )
    @app_commands.autocomplete(action_type=audit_action_autocomplete)
    @audit_authorized()
    async def export(
        self,
        interaction: discord.Interaction,
        after: Optional[str] = None,
        before: Optional[str] = None,
        action_type: Optional[int] = None,
        user_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> None:
        if interaction.guild_id is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        await interaction.response.defer(ephemeral=True, thinking=True)
        lower, upper = make_time_bounds(after, before)
        if action_type is not None and action_type < 0:
            raise AuditInputError("action_type 必须是非负整数。")
        actor_id = parse_optional_snowflake(user_id, "user_id")
        subject_id = parse_optional_snowflake(target_id, "target_id")
        query = AuditExportQuery(
            guild_id=interaction.guild_id,
            action_type=action_type,
            lower_entry_id=lower,
            upper_entry_id=upper,
            user_id=actor_id,
            target_id=subject_id,
        )
        total_count = await self.client.store.export_count(query)
        if total_count == 0:
            await interaction.edit_original_response(content="没有匹配的归档日志。")
            return
        started = await self.client.run_export(
            interaction.guild_id,
            interaction.user,
            after=after,
            before=before,
            action_type=action_type,
            user_id=user_id,
            target_id=target_id,
            interaction=interaction,
            total_count=total_count,
        )
        if not started:
            await interaction.edit_original_response(
                content="本服务器已有导出任务正在运行，请稍后再试。"
            )
            return
        await interaction.edit_original_response(
            content=(
                f"已开始导出，共 {total_count:,} 条，"
                "完成后将通过私信发送 CSV 文件。"
            )
        )

    @app_commands.command(name="role-add", description="授权身份组使用审核日志查询命令")
    @app_commands.describe(role="要授权的身份组")
    @guild_owner_only()
    async def role_add(
        self, interaction: discord.Interaction, role: discord.Role
    ) -> None:
        if interaction.guild_id is None or role.is_default():
            raise AuditInputError("everyone 身份组不能授权。")
        await interaction.response.defer(ephemeral=True, thinking=True)
        added = await self.client.store.add_role(interaction.guild_id, role.id)
        self.client.role_cache.pop(interaction.guild_id, None)
        message = "已授权" if added else "该身份组此前已授权"
        await interaction.edit_original_response(
            content=f"{message}：{role.mention} (`{role.id}`)。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @app_commands.command(name="role-remove", description="移除身份组的审核日志查询权限")
    @app_commands.describe(
        role="选择当前身份组",
        role_id="手动填写身份组 ID，适用于已删除的身份组",
    )
    @guild_owner_only()
    async def role_remove(
        self,
        interaction: discord.Interaction,
        role: Optional[discord.Role] = None,
        role_id: Optional[str] = None,
    ) -> None:
        if interaction.guild_id is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        if role is not None and role_id:
            raise AuditInputError("role 与 role_id 不能同时填写。")
        if role is not None:
            selected_id = role.id
            label = role.mention
        elif role_id and SNOWFLAKE_PATTERN.fullmatch(role_id.strip()):
            selected_id = int(role_id)
            if not 0 < selected_id <= 9_223_372_036_854_775_807:
                raise AuditInputError("role_id 超出 SQLite 整数范围。")
            label = "身份组 ID"
        else:
            raise AuditInputError("请提供身份组或有效的身份组 ID。")
        await interaction.response.defer(ephemeral=True, thinking=True)
        removed = await self.client.store.remove_role(
            interaction.guild_id, selected_id
        )
        self.client.role_cache.pop(interaction.guild_id, None)
        await interaction.edit_original_response(
            content=("已移除" if removed else "该身份组本就不在授权列表")
            + f"：{label} (`{selected_id}`)。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @app_commands.command(name="role-list", description="查看已获审核日志查询权限的身份组")
    @guild_owner_only()
    async def role_list(self, interaction: discord.Interaction) -> None:
        if interaction.guild_id is None or interaction.guild is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        await interaction.response.defer(ephemeral=True, thinking=True)
        role_ids = await self.client.store.list_roles(interaction.guild_id)
        lines = []
        for role_id in role_ids:
            role = interaction.guild.get_role(role_id)
            lines.append(
                f"{role.mention if role else '已删除的身份组'} (`{role_id}`)"
            )
        visible = lines[:35]
        if len(lines) > len(visible):
            visible.append(f"… 另有 {len(lines) - len(visible)} 个")
        await interaction.edit_original_response(
            content="已授权身份组：\n"
            + ("\n".join(visible) if visible else "（无）"),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @app_commands.command(name="role-clear", description="清空所有已授权的审核日志查询身份组")
    @app_commands.describe(confirm="确认清空全部已授权身份组")
    @guild_owner_only()
    async def role_clear(
        self, interaction: discord.Interaction, confirm: bool
    ) -> None:
        if interaction.guild_id is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        await interaction.response.defer(ephemeral=True, thinking=True)
        if not confirm:
            await interaction.edit_original_response(content="未更改任何身份组。")
            return
        count = await self.client.store.clear_roles(interaction.guild_id)
        self.client.role_cache.pop(interaction.guild_id, None)
        await interaction.edit_original_response(
            content=f"已清除 {count} 条身份组授权记录。"
        )

    @app_commands.command(name="backfill", description="启动 REST 审核日志历史回填任务")
    @app_commands.describe(full="重置同步游标并重放 Discord 当前保留的全部条目")
    @guild_owner_only()
    async def backfill(
        self, interaction: discord.Interaction, full: bool = False
    ) -> None:
        if interaction.guild is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        me = interaction.guild.me
        if me is None or not me.guild_permissions.view_audit_log:
            raise AuditInputError("机器人在本服务器缺少“查看审核日志”权限。")
        started, state = self.client.start_manual_backfill(interaction.guild, full)
        await interaction.response.send_message(
            ("已启动" if started else "未启动") + f"：{state}。",
            ephemeral=True,
        )

    @app_commands.command(name="stats", description="查看归档库与同步状态")
    @audit_authorized()
    async def stats(self, interaction: discord.Interaction) -> None:
        if interaction.guild_id is None:
            raise AuditInputError("本命令仅限服务器内使用。")
        await interaction.response.defer(ephemeral=True, thinking=True)
        stats = await self.client.cached_guild_stats(interaction.guild_id)
        staging_count = await self.client.store.count_staging()
        dead_letter_count = await self.client.store.count_dead_letters(
            interaction.guild_id
        )
        metrics = self.client.sync_metrics.get(interaction.guild_id, {})
        checkpoint = stats["checkpoint"]
        checkpoint_time = (
            "无"
            if checkpoint is None
            else f"<t:{snowflake_ms(checkpoint) // 1000}:F> (`{checkpoint}`)"
        )
        active = interaction.guild_id in self.client.backfill_tasks
        embed = discord.Embed(title="审核日志归档统计", colour=discord.Colour.green())
        first_time = (
            "无"
            if stats["min_created_at_ms"] is None
            else f"<t:{stats['min_created_at_ms'] // 1000}:f>"
        )
        last_time = (
            "无"
            if stats["max_created_at_ms"] is None
            else f"<t:{stats['max_created_at_ms'] // 1000}:f>"
        )
        last_sync_at_ms = metrics.get("last_sync_at_ms")
        last_sync = (
            "无"
            if last_sync_at_ms is None
            else f"<t:{last_sync_at_ms // 1000}:F>"
        )
        embed.add_field(name="归档条目数", value=f"{stats['count']:,}")
        free_bytes = disk_free_bytes()
        disk_value = f"{free_bytes / 1024**3:.2f} GB"
        if free_bytes < DISK_MIN_FREE_BYTES:
            disk_value += "\n⚠ 磁盘空间不足"
        embed.add_field(name="磁盘剩余", value=disk_value)
        staging_value = f"{staging_count:,}"
        if staging_count > STAGING_BACKLOG_WARN:
            staging_value += "\n⚠ 处理队列积压异常"
            LOG.warning(
                "Staging backlog exceeds threshold; backlog=%s threshold=%s guild=%s",
                staging_count,
                STAGING_BACKLOG_WARN,
                interaction.guild_id,
            )
        embed.add_field(name="处理队列积压", value=staging_value)
        embed.add_field(
            name="事件缓冲池",
            value=f"{self.client.staging_buffer.qsize():,}/{STAGING_BATCH_SIZE:,}",
        )
        embed.add_field(
            name="等待处理数", value=f"{self.client.staging_waiters:,}"
        )
        embed.add_field(
            name="入队超时",
            value=(
                f"全局={self.client.staging_admission_timeouts:,}"
                f" · 本服={metrics.get('staging_admission_timeouts', 0):,}"
            ),
        )
        embed.add_field(
            name="丢弃事件数", value=f"{self.client.dropped_events:,}"
        )
        embed.add_field(
            name="服务器入库失败",
            value=f"{metrics.get('cumulative_dropped', 0):,}",
        )
        embed.add_field(
            name="上次自动修复抓取量",
            value=f"{metrics.get('last_fetched_count', 0):,}",
        )
        embed.add_field(
            name="累计抓取数",
            value=f"{metrics.get('cumulative_fetched', 0):,}",
        )
        embed.add_field(
            name="失效 API 队列",
            value=(
                f"累计={dead_letter_count:,}\n"
                f"本次={metrics.get('dead_letters_this_run', 0):,}"
                f" · 最近记录={metrics.get('last_dead_letter_entry_id', '无')}"
            ),
        )
        embed.add_field(
            name="上次自动修复耗时",
            value=f"{metrics.get('last_sync_duration_ms', 0):,} 毫秒",
        )
        embed.add_field(name="最近自动修复", value=last_sync, inline=False)
        embed.add_field(name="记录归档范围", value=f"{first_time} → {last_time}", inline=False)
        embed.add_field(name="当前同步进度", value=checkpoint_time, inline=False)
        writer_alive = bool(
            self.client.staging_writer_task
            and not self.client.staging_writer_task.done()
        )
        worker_alive = bool(
            self.client.worker_task and not self.client.worker_task.done()
        )
        health = clean_text(self.client.unhealthy_reason or "健康", 700)
        embed.add_field(
            name="后台服务状态",
            value=(
                f"写入进程={'运行中' if writer_alive else '已停止'}\n"
                f"消费进程={'运行中' if worker_alive else '已停止'}\n"
                f"运行状态={health}"
            ),
            inline=False,
        )
        persistent_dirty = (
            interaction.guild_id in self.client.dirty_guilds
            or dead_letter_count > 0
        )
        embed.add_field(
            name="运行状态",
            value=(
                f"手动同步历史={'进行中' if active else '空闲'}\n"
                f"数据待刷新={'是' if persistent_dirty else '否'}\n"
                f"API 频率锁={'占用' if self.client.rest_lock.locked() else '空闲'}\n"
                f"同步间隔={SYNC_INTERVAL_MINUTES} 分钟"
            ),
            inline=False,
        )
        await interaction.edit_original_response(embed=embed)

    async def on_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ) -> None:
        original = getattr(error, "original", error)
        if isinstance(error, app_commands.CheckFailure):
            message = "你没有权限使用此审核日志命令。"
        elif isinstance(original, AuditInputError):
            message = str(original)
        else:
            LOG.error(
                "Slash command failed: %s",
                getattr(interaction.command, "qualified_name", "unknown"),
                exc_info=(type(original), original, original.__traceback__),
            )
            message = "审核日志命令执行失败，请联系管理员查看机器人日志。"
        if interaction.response.is_done():
            if (
                interaction.response.type
                is discord.InteractionResponseType.deferred_channel_message
            ):
                await interaction.edit_original_response(
                    content=message, embed=None, view=None
                )
            else:
                await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)


class AuditArchiver(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.moderation = True
        super().__init__(intents=intents)

        self.store = SQLiteStore(DB_PATH)
        self.staging_buffer: asyncio.Queue[AuditRow] = asyncio.Queue(
            maxsize=STAGING_BATCH_SIZE
        )
        self.staging_slots = asyncio.Semaphore(STAGING_BATCH_SIZE)
        self.staging_inflight = 0
        self.staging_waiters = 0
        self.staging_admission_timeouts = 0
        self.staging_idle = asyncio.Event()
        self.staging_idle.set()
        self.staging_writer_task: Optional[asyncio.Task[None]] = None
        self.worker_task: Optional[asyncio.Task[None]] = None
        self.rest_lock = asyncio.Lock()
        self.disk_pressure = False
        self.dirty_guilds: set[int] = set()
        self.dropped_events = 0
        self.sync_metrics: dict[int, dict[str, int]] = {}
        self._stats_cache: dict[int, tuple[float, dict[str, Any]]] = {}
        self._stats_cache_lock = asyncio.Lock()
        self.unhealthy_reason: Optional[str] = None
        self.accepting_events = True
        self.role_cache: dict[int, tuple[float, frozenset[int]]] = {}
        self.backfill_tasks: dict[int, asyncio.Task[None]] = {}
        self.export_tasks: dict[int, asyncio.Task[None]] = {}
        self.tree = app_commands.CommandTree(self)
        self.tree.add_command(AuditCommands(self))

    def tracked(self, guild_id: int) -> bool:
        return not TARGET_GUILDS or guild_id in TARGET_GUILDS

    def background_task_done(
        self, name: str, task: asyncio.Task[None]
    ) -> None:
        if task.cancelled():
            if not self.accepting_events:
                return
            reason = f"{name} was cancelled unexpectedly"
            error: Optional[BaseException] = None
        else:
            error = task.exception()
            reason = (
                f"{name} stopped unexpectedly"
                if error is None
                else f"{name} failed: {type(error).__name__}: {error}"
            )
        self.unhealthy_reason = reason
        if error is None:
            LOG.critical(reason)
        else:
            LOG.critical(
                reason,
                exc_info=(type(error), error, error.__traceback__),
            )

    async def setup_hook(self) -> None:
        await self.store.open()
        self.staging_writer_task = asyncio.create_task(
            self.staging_writer(), name="audit-staging-writer"
        )
        self.staging_writer_task.add_done_callback(
            lambda task: self.background_task_done("staging writer", task)
        )
        self.worker_task = asyncio.create_task(
            self.database_worker(), name="audit-database-worker"
        )
        self.worker_task.add_done_callback(
            lambda task: self.background_task_done("database worker", task)
        )
        self.maintenance.start()
        await self.sync_application_commands()

    async def sync_application_commands(self) -> None:
        mode = COMMAND_SYNC_MODE
        if mode == "none":
            LOG.info("Slash command sync skipped (AUDIT_COMMAND_SYNC_MODE=none)")
            return
        if mode == "global":
            commands = await self.tree.sync()
            LOG.info("Synced %s global slash command roots", len(commands))
            return
        if mode == "guild":
            if not COMMAND_GUILD_IDS:
                raise RuntimeError(
                    "AUDIT_COMMAND_GUILD_IDS or TARGET_GUILD_IDS is required for guild sync"
                )
            for guild_id in sorted(COMMAND_GUILD_IDS):
                guild_object = discord.Object(id=guild_id)
                self.tree.copy_global_to(guild=guild_object)
                commands = await self.tree.sync(guild=guild_object)
                LOG.info(
                    "Synced %s slash command roots to guild %s",
                    len(commands),
                    guild_id,
                )
            return
        raise RuntimeError(
            "AUDIT_COMMAND_SYNC_MODE must be none, guild, or global"
        )

    async def cached_guild_stats(self, guild_id: int) -> dict[str, Any]:
        current = time.monotonic()
        cached = self._stats_cache.get(guild_id)
        if cached is not None and cached[0] > current:
            return dict(cached[1])
        async with self._stats_cache_lock:
            current = time.monotonic()
            cached = self._stats_cache.get(guild_id)
            if cached is not None and cached[0] > current:
                return dict(cached[1])
            result = await self.store.guild_stats(guild_id)
            self._stats_cache[guild_id] = (
                time.monotonic() + STATS_CACHE_SECONDS,
                dict(result),
            )
            return dict(result)

    async def authorized_role_ids(self, guild_id: int) -> frozenset[int]:
        cached = self.role_cache.get(guild_id)
        current = time.monotonic()
        if cached is not None and cached[0] > current:
            return cached[1]
        role_ids = frozenset(await self.store.list_roles(guild_id))
        self.role_cache[guild_id] = (current + 60.0, role_ids)
        return role_ids

    async def is_audit_authorized(self, interaction: discord.Interaction) -> bool:
        guild = interaction.guild
        if guild is None or interaction.guild_id is None:
            return False
        if guild.owner_id == interaction.user.id:
            return True
        member = interaction.user
        if not isinstance(member, discord.Member):
            return False
        if ALLOW_VIEW_AUDIT_LOG_PERMISSION and member.guild_permissions.view_audit_log:
            return True
        allowed = await self.authorized_role_ids(interaction.guild_id)
        return any(role.id in allowed for role in member.roles)

    async def run_export(
        self,
        guild_id: int,
        requester: discord.abc.Messageable,
        *,
        after: Optional[str],
        before: Optional[str],
        action_type: Optional[int],
        user_id: Optional[str],
        target_id: Optional[str],
        interaction: discord.Interaction,
        total_count: int,
    ) -> bool:
        existing = self.export_tasks.get(guild_id)
        if existing is not None and not existing.done():
            return False
        lower, upper = make_time_bounds(after, before)
        query = AuditExportQuery(
            guild_id=guild_id,
            action_type=action_type,
            lower_entry_id=lower,
            upper_entry_id=upper,
            user_id=parse_optional_snowflake(user_id, "user_id"),
            target_id=parse_optional_snowflake(target_id, "target_id"),
        )
        task = asyncio.create_task(
            self._export_csv(
                query,
                requester,
                interaction,
                total_count,
            ),
            name=f"audit-csv-export:{guild_id}:{interaction.user.id}",
        )
        self.export_tasks[guild_id] = task
        task.add_done_callback(
            lambda finished, export_guild_id=guild_id: self.finish_export(
                export_guild_id,
                finished,
            )
        )
        return True

    def finish_export(self, guild_id: int, task: asyncio.Task[None]) -> None:
        if self.export_tasks.get(guild_id) is task:
            self.export_tasks.pop(guild_id, None)
        if task.cancelled():
            LOG.warning("Audit CSV export cancelled for guild %s", guild_id)
            return
        error = task.exception()
        if error is not None:
            LOG.error(
                "Audit CSV export task failed for guild %s",
                guild_id,
                exc_info=(type(error), error, error.__traceback__),
            )

    async def _export_csv(
        self,
        query: AuditExportQuery,
        requester: discord.abc.Messageable,
        interaction: discord.Interaction,
        total_count: int,
    ) -> None:
        temporary_directory: Optional[Path] = None
        try:
            temporary_directory = Path(
                tempfile.mkdtemp(prefix=f"audit-export-{query.guild_id}-")
            )
            writer = ExportCsvWriter(temporary_directory, query.guild_id)
            last_entry_id: Optional[int] = None
            exported_count = 0
            sent_parts = 0
            dm_available = True
            while exported_count < total_count:
                rows = await self.store.export_fetch_batch(
                    query,
                    last_entry_id,
                    min(EXPORT_BATCH_SIZE, total_count - exported_count),
                )
                if not rows:
                    break
                completed = await asyncio.to_thread(writer.append_rows, rows)
                exported_count += len(rows)
                last_entry_id = rows[-1]["entry_id"]
                for csv_path in completed:
                    sent_parts += 1
                    dm_available = await self._send_export_part(
                        requester,
                        interaction,
                        csv_path,
                        sent_parts,
                        total_count,
                        dm_available,
                    )
                await asyncio.sleep(0)

            for csv_path in await asyncio.to_thread(writer.finish):
                sent_parts += 1
                dm_available = await self._send_export_part(
                    requester,
                    interaction,
                    csv_path,
                    sent_parts,
                    total_count,
                    dm_available,
                )
            if exported_count == 0:
                with contextlib.suppress(discord.HTTPException):
                    await interaction.followup.send(
                        "导出期间匹配记录已发生变化，当前没有可导出的日志。",
                        ephemeral=True,
                    )
            LOG.info(
                "Audit CSV export completed guild=%s rows=%s expected=%s parts=%s",
                query.guild_id,
                exported_count,
                total_count,
                sent_parts,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.exception("Audit CSV export failed for guild %s", query.guild_id)
            with contextlib.suppress(discord.HTTPException):
                await interaction.followup.send(
                    f"CSV 导出失败：{type(exc).__name__}。请联系管理员查看日志。",
                    ephemeral=True,
                )
        finally:
            if temporary_directory is not None:
                await asyncio.to_thread(shutil.rmtree, temporary_directory, True)

    async def _send_export_part(
        self,
        requester: discord.abc.Messageable,
        interaction: discord.Interaction,
        csv_path: Path,
        part_number: int,
        total_count: int,
        dm_available: bool,
    ) -> bool:
        zip_path = await asyncio.to_thread(zip_export_csv, csv_path)
        try:
            zip_size = zip_path.stat().st_size
            if zip_size >= EXPORT_ATTACHMENT_MAX_BYTES:
                raise RuntimeError(
                    f"compressed export part exceeds attachment limit: {zip_size}"
                )
            content = f"审核日志 CSV 导出，第 {part_number} 部分，共 {total_count:,} 条。"
            if dm_available:
                attachment = discord.File(zip_path, filename=zip_path.name)
                try:
                    await requester.send(content, file=attachment)
                    return True
                except discord.Forbidden:
                    dm_available = False
                finally:
                    attachment.close()
            attachment = discord.File(zip_path, filename=zip_path.name)
            try:
                await interaction.followup.send(
                    "私信未开启，已在此处发送。\n" + content,
                    file=attachment,
                    ephemeral=False,
                )
            finally:
                attachment.close()
            return dm_available
        finally:
            with contextlib.suppress(OSError):
                csv_path.unlink()
            with contextlib.suppress(OSError):
                zip_path.unlink()

    def start_manual_backfill(
        self, guild: discord.Guild, full: bool
    ) -> tuple[bool, str]:
        existing = self.backfill_tasks.get(guild.id)
        if existing is not None and not existing.done():
            return False, "已有手动回填任务正在运行"
        task = asyncio.create_task(
            self.manual_backfill(guild, full),
            name=f"manual-audit-backfill:{guild.id}",
        )
        self.backfill_tasks[guild.id] = task
        task.add_done_callback(
            lambda finished, guild_id=guild.id: self.finish_manual_backfill(
                guild_id, finished
            )
        )
        return True, "完整重放保留期内历史" if full else "增量重放"

    def finish_manual_backfill(
        self, guild_id: int, task: asyncio.Task[None]
    ) -> None:
        if self.backfill_tasks.get(guild_id) is task:
            self.backfill_tasks.pop(guild_id, None)
        if task.cancelled():
            LOG.warning("Manual audit backfill cancelled for guild %s", guild_id)
            return
        error = task.exception()
        if error is not None:
            LOG.error(
                "Manual audit backfill failed for guild %s",
                guild_id,
                exc_info=(type(error), error, error.__traceback__),
            )
        else:
            LOG.info("Manual audit backfill completed for guild %s", guild_id)

    async def manual_backfill(self, guild: discord.Guild, full: bool) -> None:
        # Manual and scheduled REST crawls share this lock and cannot overlap.
        async with self.rest_lock:
            if full:
                self.dirty_guilds.add(guild.id)
                # Deleting the durable cursor is fail-safe: after a crash the next
                # maintenance pass also starts from the oldest retained entry.
                await self.store.reset_checkpoint(guild.id)
                LOG.info("Reset audit backfill cursor for guild %s", guild.id)
            await self.backfill_guild(guild, force_from_zero=full)
            if not self.disk_pressure:
                await self.refresh_mutable_entries(guild)

    async def on_ready(self) -> None:
        LOG.info("Connected as %s; discord.py=%s", self.user, discord.__version__)

    def record_staging_failure(self, guild_counts: Mapping[int, int]) -> None:
        for guild_id, count in guild_counts.items():
            self.dirty_guilds.add(guild_id)
            self.dropped_events += count
            metrics = self.sync_metrics.setdefault(guild_id, {})
            metrics["cumulative_dropped"] = (
                metrics.get("cumulative_dropped", 0) + count
            )
        if guild_counts:
            LOG.error(
                "Staging data loss recorded; lost=%s guilds=%s",
                sum(guild_counts.values()),
                sorted(guild_counts),
            )

    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        if not self.accepting_events or not self.tracked(entry.guild.id):
            return
        self.staging_inflight += 1
        self.staging_idle.clear()
        acquired = False
        try:
            # Bound both accepted rows and callbacks waiting for disk admission.
            self.staging_waiters += 1
            try:
                await asyncio.wait_for(
                    self.staging_slots.acquire(),
                    timeout=STAGING_ADMISSION_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                self.staging_admission_timeouts += 1
                metrics = self.sync_metrics.setdefault(entry.guild.id, {})
                metrics["staging_admission_timeouts"] = (
                    metrics.get("staging_admission_timeouts", 0) + 1
                )
                self.record_staging_failure({entry.guild.id: 1})
                LOG.error(
                    "Timed out admitting audit entry %s to staging",
                    entry.id,
                )
                return
            finally:
                self.staging_waiters -= 1
            acquired = True
            row = entry_to_row(entry, "gateway")
            self.staging_buffer.put_nowait(row)
            acquired = False
        except Exception:
            if acquired:
                self.staging_slots.release()
            self.record_staging_failure({entry.guild.id: 1})
            LOG.exception("Could not buffer audit entry %s for staging", entry.id)
        finally:
            self.staging_inflight -= 1
            if self.staging_inflight == 0:
                self.staging_idle.set()

    async def staging_writer(self) -> None:
        while True:
            first = await self.staging_buffer.get()
            batch = [first]
            deadline = asyncio.get_running_loop().time() + STAGING_FLUSH_SECONDS
            while len(batch) < STAGING_BATCH_SIZE:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    batch.append(
                        await asyncio.wait_for(
                            self.staging_buffer.get(), timeout=remaining
                        )
                    )
                except asyncio.TimeoutError:
                    break

            delay = 0.2
            staged = False
            try:
                for attempt in range(STAGING_WRITE_RETRIES):
                    try:
                        await self.store.stage(batch)
                        staged = True
                        break
                    except sqlite3.Error:
                        LOG.exception(
                            "SQLite staging write failed; attempt=%s/%s",
                            attempt + 1,
                            STAGING_WRITE_RETRIES,
                        )
                        if attempt + 1 < STAGING_WRITE_RETRIES:
                            await asyncio.sleep(delay)
                            delay = min(delay * 2.0, 3.2)
            except Exception:
                LOG.exception("Unexpected staging writer failure")

            if not staged:
                guild_counts: dict[int, int] = {}
                for row in batch:
                    guild_counts[row.guild_id] = guild_counts.get(row.guild_id, 0) + 1
                self.record_staging_failure(guild_counts)
            for _ in batch:
                self.staging_buffer.task_done()
                self.staging_slots.release()

    async def database_worker(self) -> None:
        delay = 0.5
        while True:
            try:
                result = await self.store.pop_staging(STAGING_CONSUME_SIZE)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.critical("Staging consumption failed; retrying", exc_info=True)
                await asyncio.sleep(delay)
                delay = min(delay * 2.0, 30.0)
                continue

            delay = 0.5
            if result.invalid_count:
                self.record_staging_failure(dict(result.invalid_by_guild))
                LOG.error(
                    "Discarded %s malformed staging rows after durable read",
                    result.invalid_count,
                )
            if result.consumed_count == 0:
                await asyncio.sleep(0.25)

    def replay_cursor(self, checkpoint: int) -> int:
        if checkpoint == 0:
            return 0
        checkpoint_time = discord.utils.snowflake_time(checkpoint)
        start_time = checkpoint_time - dt.timedelta(seconds=REPLAY_OVERLAP_SECONDS)
        # Discord's `after` cursor is exclusive. Subtracting one makes the
        # overlap boundary inclusive, including a snowflake with low bits 0.
        return max(0, discord.utils.time_snowflake(start_time, high=False) - 1)

    def record_rest_dead_letter(
        self,
        guild_id: int,
        entry_id: int,
        source: str,
        error: Exception,
    ) -> DeadLetter:
        metrics = self.sync_metrics.setdefault(guild_id, {})
        metrics["dead_letters_this_run"] = (
            metrics.get("dead_letters_this_run", 0) + 1
        )
        metrics["last_dead_letter_entry_id"] = entry_id
        self.dirty_guilds.add(guild_id)
        LOG.error(
            "Could not convert REST audit entry guild=%s entry=%s source=%s",
            guild_id,
            entry_id,
            source,
            exc_info=(type(error), error, error.__traceback__),
        )
        try:
            error_text = str(error)[:1000]
        except Exception:
            error_text = "Could not stringify conversion error"
        return DeadLetter(
            guild_id=guild_id,
            entry_id=entry_id,
            source=source,
            error_type=type(error).__name__,
            error_text=error_text,
            seen_at_ms=now_ms(),
        )

    def update_sync_metrics(
        self,
        guild_id: int,
        *,
        fetched_count: int,
        checkpoint_id: int,
        started_at: float,
        cumulative_base: int,
    ) -> None:
        metrics = self.sync_metrics.setdefault(guild_id, {})
        metrics.update(
            last_sync_at_ms=now_ms(),
            last_fetched_count=fetched_count,
            last_checkpoint_id=checkpoint_id,
            last_sync_duration_ms=int((time.monotonic() - started_at) * 1000),
            cumulative_fetched=cumulative_base + fetched_count,
        )
        metrics.setdefault("cumulative_dropped", 0)

    async def backfill_guild(
        self, guild: discord.Guild, *, force_from_zero: bool = False
    ) -> None:
        started_at = time.monotonic()
        free_bytes = disk_free_bytes()
        if free_bytes < DISK_MIN_FREE_BYTES:
            self.disk_pressure = True
            LOG.warning(
                "Disk full during backfill; aborting this pass for guild %s",
                guild.id,
            )
            return
        self.disk_pressure = False
        old_checkpoint = (
            0 if force_from_zero else await self.store.checkpoint(guild.id)
        )
        checkpoint = old_checkpoint
        # after=0 is strictly before every real audit-log snowflake, so the
        # oldest Discord-retained entry is included in a full replay.
        cursor = 0 if force_from_zero else self.replay_cursor(checkpoint)
        if AUDIT_RETENTION_DAYS > 0:
            cutoff_ms = now_ms() - AUDIT_RETENTION_DAYS * 86_400_000
            retention_cursor = max(
                0,
                ((cutoff_ms - DISCORD_EPOCH_MS) << 22) - 1,
            )
            cursor = max(cursor, retention_cursor)
        highest = checkpoint
        committed_highest = checkpoint
        fetched_count = 0
        metrics = self.sync_metrics.setdefault(guild.id, {})
        metrics["dead_letters_this_run"] = 0
        cumulative_base = metrics.get("cumulative_fetched", 0)
        batch: list[AuditRow] = []
        dead_letters: list[DeadLetter] = []
        last_refresh = time.monotonic()

        after = discord.Object(id=cursor)
        async for entry in guild.audit_logs(
            limit=None,
            after=after,
            oldest_first=True,
        ):
            fetched_count += 1
            highest = max(highest, entry.id)
            try:
                row = entry_to_row(entry, "rest_backfill")
            except Exception as exc:
                dead_letters.append(
                    self.record_rest_dead_letter(
                        guild.id, entry.id, "rest_backfill", exc
                    )
                )
            else:
                batch.append(row)
            if len(batch) + len(dead_letters) >= 100:
                await self.store.upsert(
                    batch,
                    checkpoint=(guild.id, highest),
                    dead_letters=dead_letters,
                )
                committed_highest = highest
                batch.clear()
                dead_letters.clear()
                self.update_sync_metrics(
                    guild.id,
                    fetched_count=fetched_count,
                    checkpoint_id=highest,
                    started_at=started_at,
                    cumulative_base=cumulative_base,
                )
            if fetched_count % 100 == 0:
                free_bytes = disk_free_bytes()
                if free_bytes < DISK_MIN_FREE_BYTES:
                    self.disk_pressure = True
                    LOG.warning(
                        "Disk full during backfill; aborting this pass for guild %s",
                        guild.id,
                    )
                    break
                # A first 45-day crawl can take hours. Keep mutable entries fresh.
                if time.monotonic() - last_refresh >= 600.0:
                    await self.refresh_mutable_entries(guild)
                    last_refresh = time.monotonic()

        if batch or dead_letters or highest > committed_highest:
            await self.store.upsert(
                batch,
                checkpoint=(guild.id, highest),
                dead_letters=dead_letters,
            )
        self.update_sync_metrics(
            guild.id,
            fetched_count=fetched_count,
            checkpoint_id=highest,
            started_at=started_at,
            cumulative_base=cumulative_base,
        )
        LOG.info(
            "Audit self-heal completed guild=%s fetched=%s checkpoint=%s->%s duration_ms=%s",
            guild.id,
            fetched_count,
            old_checkpoint,
            highest,
            self.sync_metrics[guild.id]["last_sync_duration_ms"],
        )
        if await self.store.count_dead_letters(guild.id):
            self.dirty_guilds.add(guild.id)
        else:
            self.dirty_guilds.discard(guild.id)

    async def refresh_mutable_entries(self, guild: discord.Guild) -> None:
        actions = (
            discord.AuditLogAction.message_delete,
            discord.AuditLogAction.member_move,
            discord.AuditLogAction.member_disconnect,
        )
        for action in actions:
            rows: list[AuditRow] = []
            dead_letters: list[DeadLetter] = []
            async for entry in guild.audit_logs(limit=100, action=action):
                try:
                    rows.append(entry_to_row(entry, "rest_refresh"))
                except Exception as exc:
                    dead_letters.append(
                        self.record_rest_dead_letter(
                            guild.id, entry.id, "rest_refresh", exc
                        )
                    )
            await self.store.upsert(rows, dead_letters=dead_letters)
        if await self.store.count_dead_letters(guild.id):
            self.dirty_guilds.add(guild.id)
        else:
            self.dirty_guilds.discard(guild.id)

    @tasks.loop(minutes=SYNC_INTERVAL_MINUTES, reconnect=True)
    async def maintenance(self) -> None:
        async with self.rest_lock:
            free_bytes = disk_free_bytes()
            self.disk_pressure = free_bytes < DISK_MIN_FREE_BYTES
            if self.disk_pressure:
                LOG.warning(
                    "Disk pressure: free_bytes=%s < threshold=%s; skipping REST backfill",
                    free_bytes,
                    DISK_MIN_FREE_BYTES,
                )
            else:
                for guild in self.guilds:
                    if not self.tracked(guild.id):
                        continue
                    me = guild.me
                    if me is None or not me.guild_permissions.view_audit_log:
                        LOG.error("Missing View Audit Log permission in guild %s", guild.id)
                        continue
                    try:
                        # Reconcile missing entries first, then refresh mutable aggregate rows.
                        await self.backfill_guild(guild)
                        if self.disk_pressure:
                            break
                        await self.refresh_mutable_entries(guild)
                    except discord.Forbidden:
                        self.dirty_guilds.add(guild.id)
                        LOG.exception("Audit log access denied for guild %s", guild.id)
                    except discord.HTTPException:
                        self.dirty_guilds.add(guild.id)
                        LOG.exception("Audit log REST failure for guild %s", guild.id)
                    except Exception:
                        self.dirty_guilds.add(guild.id)
                        LOG.exception("Audit maintenance failed for guild %s", guild.id)

        if AUDIT_RETENTION_DAYS > 0:
            cutoff_ms = now_ms() - AUDIT_RETENTION_DAYS * 86_400_000
            try:
                pruned_entries, pruned_dead_letters = await self.store.prune_before(
                    cutoff_ms,
                    (guild.id for guild in self.guilds if self.tracked(guild.id)),
                )
                if pruned_entries or pruned_dead_letters:
                    self._stats_cache.clear()
                    LOG.info(
                        "Audit retention pruned entries=%s dead_letters=%s cutoff_ms=%s",
                        pruned_entries,
                        pruned_dead_letters,
                        cutoff_ms,
                    )
                    if AUDIT_VACUUM_AFTER_PRUNE:
                        await self.store.vacuum()
            except Exception:
                LOG.exception("Audit retention pruning failed")

        try:
            staging_count = await self.store.count_staging()
            if staging_count > STAGING_BACKLOG_WARN:
                LOG.warning(
                    "Staging backlog exceeds threshold; backlog=%s threshold=%s",
                    staging_count,
                    STAGING_BACKLOG_WARN,
                )
            busy, log_frames, checkpointed_frames = await self.store.checkpoint_wal()
            if busy:
                LOG.warning(
                    "WAL checkpoint remained busy; log_frames=%s checkpointed=%s",
                    log_frames,
                    checkpointed_frames,
                )
            else:
                LOG.info(
                    "WAL checkpoint completed; log_frames=%s checkpointed=%s",
                    log_frames,
                    checkpointed_frames,
                )
        except Exception:
            LOG.exception("SQLite maintenance failed")

    @maintenance.before_loop
    async def before_maintenance(self) -> None:
        await self.wait_until_ready()

    async def close(self) -> None:
        if self.is_closed():
            return
        self.accepting_events = False

        task = self.maintenance.get_task()
        self.maintenance.cancel()
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task

        manual_tasks = list(self.backfill_tasks.values())
        for manual_task in manual_tasks:
            manual_task.cancel()
        for manual_task in manual_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await manual_task
        self.backfill_tasks.clear()

        export_tasks = list(self.export_tasks.values())
        for export_task in export_tasks:
            export_task.cancel()
        for export_task in export_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await export_task
        self.export_tasks.clear()

        await super().close()

        # Wait for Gateway callbacks that passed the acceptance gate, then persist
        # every row accepted into the small in-memory staging buffer.
        await self.staging_idle.wait()
        await self.staging_buffer.join()
        if self.staging_writer_task is not None:
            self.staging_writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.staging_writer_task

        # Durable staging rows may remain and are safely resumed next startup.
        if self.worker_task is not None:
            self.worker_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.worker_task
        await self.store.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    token = os.environ["DISCORD_TOKEN"]
    AuditArchiver().run(token, log_handler=None)
