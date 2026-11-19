"""Bounded, privacy-conscious telemetry kept separate from the publishing DB.

The PUBLIC container alone writes /telemetry/traffic.sqlite3; the ADMIN
container only reads it. Unapproved IDs and coarse referring hostnames are
retained for 90 days. No client addresses, full referrers or user agents.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

RETENTION_DAYS = 90
MAX_UNAPPROVED_IDS = 1000
MAX_REFERRERS_PER_DAY = 40
MAX_DB_PAGES = 2048  # Usually 8 MiB with SQLite's default 4096-byte pages.
COUNTER_NAMES = ("views", "requests", "successes", "denials")


def _clock() -> tuple[str, str, str]:
    now = datetime.now(timezone.utc)
    day = now.date().isoformat()
    cutoff = (now.date() - timedelta(days=RETENTION_DAYS - 1)).isoformat()
    return now.isoformat(timespec="seconds"), day, cutoff


def initialize(db_path: Path) -> None:
    """Called only in the writable public container on first startup."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path, timeout=3) as db:
        db.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA busy_timeout=3000;
            CREATE TABLE IF NOT EXISTS daily (
                day TEXT PRIMARY KEY,
                views INTEGER NOT NULL DEFAULT 0,
                requests INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                denials INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS unapproved (
                id_key TEXT PRIMARY KEY,
                battle_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_unapproved_last ON unapproved(last_seen);
            CREATE TABLE IF NOT EXISTS referrers (
                day TEXT NOT NULL,
                hostname TEXT NOT NULL,
                views INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (day, hostname)
            );
        """)
        db.execute("PRAGMA max_page_count=" + str(MAX_DB_PAGES))


def _open_write(path: Path):
    db = sqlite3.connect(path, timeout=3)
    db.execute("PRAGMA busy_timeout=3000")
    # max_page_count is connection-local; enforce the cap on every writer.
    db.execute("PRAGMA max_page_count=" + str(MAX_DB_PAGES))
    return db


def _prune(db: sqlite3.Connection, cutoff: str) -> None:
    db.execute("DELETE FROM daily WHERE day < ?", (cutoff,))
    db.execute("DELETE FROM referrers WHERE day < ?", (cutoff,))
    db.execute("DELETE FROM unapproved WHERE last_seen < ?", (cutoff,))


def referrer_hostname(value: str, site_hostname: str | None) -> str | None:
    """Capture only the referring hostname, never URL paths or query strings."""
    if not value or len(value) > 2048:
        return None
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"}:
            return None
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,98}[a-z0-9])?", hostname):
            return None
        if hostname == (site_hostname or "").lower().rstrip("."):
            return None
        return hostname
    except ValueError:
        return None


def record_pageview(path: Path, *, referer: str = "", site_hostname: str | None = None) -> None:
    _, day, cutoff = _clock()
    hostname = referrer_hostname(referer, site_hostname)
    with _open_write(path) as db:
        _prune(db, cutoff)
        db.execute(
            "INSERT INTO daily(day, views) VALUES (?, 1) "
            "ON CONFLICT(day) DO UPDATE SET views=views+1",
            (day,),
        )
        if hostname:
            # Untrusted Referer headers must not create unlimited DB rows.
            exists = db.execute(
                "SELECT 1 FROM referrers WHERE day=? AND hostname=?",
                (day, hostname),
            ).fetchone()
            if exists or db.execute(
                "SELECT COUNT(*) FROM referrers WHERE day=?", (day,)
            ).fetchone()[0] < MAX_REFERRERS_PER_DAY:
                db.execute(
                    "INSERT INTO referrers(day,hostname,views) VALUES (?,?,1) "
                    "ON CONFLICT(day,hostname) DO UPDATE SET views=views+1",
                    (day, hostname),
                )


def record_download(path: Path, *, outcome: str, battle_id: str | None = None) -> None:
    """Record valid, accepted download submissions; never store approved IDs."""
    if outcome not in {"success", "denied", "other"}:
        raise ValueError("Unknown download outcome")
    if outcome == "denied" and not battle_id:
        raise ValueError("A denied download requires a Battle.net ID")
    current, day, cutoff = _clock()
    with _open_write(path) as db:
        _prune(db, cutoff)
        db.execute(
            "INSERT INTO daily(day,requests,successes,denials) VALUES (?,?,?,?) "
            "ON CONFLICT(day) DO UPDATE SET requests=requests+1, "
            "successes=successes+excluded.successes, denials=denials+excluded.denials",
            (day, 1, int(outcome == "success"), int(outcome == "denied")),
        )
        if outcome == "denied":
            key = battle_id.casefold()
            existing = db.execute(
                "SELECT 1 FROM unapproved WHERE id_key=?", (key,)
            ).fetchone()
            if not existing:
                count = db.execute("SELECT COUNT(*) FROM unapproved").fetchone()[0]
                if count >= MAX_UNAPPROVED_IDS:
                    db.execute(
                        "DELETE FROM unapproved WHERE id_key = "
                        "(SELECT id_key FROM unapproved ORDER BY last_seen, id_key LIMIT 1)"
                    )
            db.execute(
                "INSERT INTO unapproved(id_key,battle_id,first_seen,last_seen,attempts) "
                "VALUES(?,?,?,?,1) "
                "ON CONFLICT(id_key) DO UPDATE SET "
                "battle_id=excluded.battle_id, last_seen=excluded.last_seen, attempts=attempts+1",
                (key, battle_id, current, current),
            )


def empty_snapshot() -> dict:
    return {
        "available": False, "retention_days": RETENTION_DAYS,
        "today": dict.fromkeys(COUNTER_NAMES, 0),
        "week": dict.fromkeys(COUNTER_NAMES, 0),
        "month": dict.fromkeys(COUNTER_NAMES, 0),
        "daily": [], "unapproved": [], "referrers": [],
    }


def snapshot(db_path: Path, approved_keys: set[str] | None = None) -> dict:
    """Admin read-only snapshot. Not exposed through public role."""
    if not db_path.is_file():
        return empty_snapshot()
    current, today, cutoff = _clock()
    last_week = (datetime.now(timezone.utc).date() - timedelta(days=6)).isoformat()
    last_month = (datetime.now(timezone.utc).date() - timedelta(days=29)).isoformat()
    with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3) as db:
        db.row_factory = sqlite3.Row
        daily = [
            dict(row) for row in db.execute(
                "SELECT day,views,requests,successes,denials FROM daily "
                "WHERE day>=? ORDER BY day DESC", (cutoff,)
            )
        ]
        def sum_window(start: str) -> dict:
            return {
                name: sum(item[name] for item in daily if item["day"] >= start)
                for name in COUNTER_NAMES
            }
        approved_keys = approved_keys or set()
        unapproved = [
            dict(row) for row in db.execute(
                "SELECT id_key,battle_id,first_seen,last_seen,attempts "
                "FROM unapproved WHERE last_seen>=? "
                "ORDER BY last_seen DESC, id_key ASC LIMIT ?",
                (cutoff, MAX_UNAPPROVED_IDS),
            )
        ]
        unapproved = [
            {key: value for key, value in item.items() if key != "id_key"}
            for item in unapproved if item["id_key"] not in approved_keys
        ]
        referrers = [
            dict(row) for row in db.execute(
                "SELECT hostname, SUM(views) AS views FROM referrers WHERE day>=? "
                "GROUP BY hostname ORDER BY views DESC, hostname LIMIT 10",
                (last_month,),
            )
        ]
    return {
        "available": True, "retention_days": RETENTION_DAYS,
        "as_of": current,
        "today": sum_window(today),
        "week": sum_window(last_week),
        "month": sum_window(last_month),
        "daily": list(reversed(daily[:14])),
        "unapproved": unapproved,
        "referrers": referrers,
    }
