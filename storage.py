"""SQLite storage: users, registration requests and WireGuard mappings."""

import sqlite3
import threading
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id    INTEGER UNIQUE NOT NULL,
    username       TEXT,
    full_name      TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'Пользователь',      -- Администратор | Пользователь
    status         TEXT NOT NULL DEFAULT 'pending',   -- active | pending | rejected
    wg_interface   TEXT,
    subnet         TEXT,
    listen_port    INTEGER,
    created_at     TEXT NOT NULL,
    decided_by     INTEGER,
    access_until   TEXT
);

CREATE TABLE IF NOT EXISTS peers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id     TEXT UNIQUE NOT NULL,
    owner_id      INTEGER NOT NULL,
    name          TEXT NOT NULL,
    private_key   TEXT NOT NULL,
    ip            TEXT NOT NULL,
    allowed_ips   TEXT DEFAULT '0.0.0.0/0',
    was_disabled  INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_wg_interface ON users(wg_interface);
CREATE INDEX IF NOT EXISTS idx_peers_owner_id ON peers(owner_id);
"""


class Storage:
    def __init__(self, db_path: str = "bot.db"):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._migrate_roles()
            self._migrate_peers_state()
            self._migrate_access()
            self._migrate_allowed_ips()
            self._migrate_static_peers()
            self._migrate_public_key()
            self._conn.commit()

    def _migrate_roles(self) -> None:
        self._conn.execute("UPDATE users SET role = 'Администратор' WHERE role = 'admin'")
        self._conn.execute("UPDATE users SET role = 'Пользователь' WHERE role = 'user'")

    def _migrate_peers_state(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(peers)")}
        if "was_disabled" not in cols:
            self._conn.execute(
                "ALTER TABLE peers ADD COLUMN was_disabled INTEGER DEFAULT 0"
            )

    def _migrate_access(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(users)")}
        if "access_until" not in cols:
            self._conn.execute("ALTER TABLE users ADD COLUMN access_until TEXT")

    def _migrate_allowed_ips(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(peers)")}
        if "allowed_ips" not in cols:
            self._conn.execute(
                "ALTER TABLE peers ADD COLUMN allowed_ips TEXT DEFAULT '0.0.0.0/0'"
            )

    def _migrate_static_peers(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(peers)")}
        if "is_static" not in cols:
            self._conn.execute(
                "ALTER TABLE peers ADD COLUMN is_static INTEGER DEFAULT 0"
            )

    def _migrate_public_key(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(peers)")}
        if "public_key" not in cols:
            self._conn.execute(
                "ALTER TABLE peers ADD COLUMN public_key TEXT DEFAULT ''"
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------ users
    def user_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def get_user(self, telegram_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_interface(self, interface: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE wg_interface = ?", (interface,)
            ).fetchone()
            return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_admins(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users WHERE role = 'Администратор' AND status = 'active'"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_pending(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users WHERE status = 'pending' ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_active(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users WHERE status = 'active' ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_expired(self, now: str) -> list[dict]:
        """Users with a set access deadline that is already in the past."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users "
                "WHERE status = 'active' AND access_until IS NOT NULL "
                "AND access_until <> '' AND access_until <= ?",
                (now,),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_expiring_soon(self, now: str, before: str) -> list[dict]:
        """Active users whose deadline falls in the interval (now, before]."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users "
                "WHERE status = 'active' AND access_until IS NOT NULL "
                "AND access_until <> '' AND access_until > ? AND access_until <= ?",
                (now, before),
            ).fetchall()
            return [dict(r) for r in rows]

    def add_user(
        self,
        telegram_id: int,
        full_name: str,
        username: str | None,
        role: str = "Пользователь",
        status: str = "active",
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO users"
                "(telegram_id, username, full_name, role, status, created_at)"
                "VALUES (?, ?, ?, ?, ?, ?)",
                (telegram_id, username, full_name, role, status, self._now()),
            )
            self._conn.commit()

    def update_user(self, telegram_id: int, **fields) -> None:
        keys = list(fields)
        with self._lock:
            self._conn.execute(
                "UPDATE users SET "
                + ", ".join(f"{k} = ?" for k in keys)
                + " WHERE telegram_id = ?",
                [fields[k] for k in keys] + [telegram_id],
            )
            self._conn.commit()

    def delete_user(self, telegram_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM users WHERE telegram_id = ?", (telegram_id,))
            self._conn.commit()

    # ------------------------------------------------------------------ peers
    def add_peer(
        self,
        router_id: str,
        owner_id: int,
        name: str,
        private_key: str,
        ip: str,
        allowed_ips: str = "0.0.0.0/0",
        is_static: int = 0,
        public_key: str = "",
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO peers"
                "(router_id, owner_id, name, private_key, ip, allowed_ips, is_static, public_key, created_at)"
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (router_id, owner_id, name, private_key, ip, allowed_ips, is_static, public_key, self._now()),
            )
            self._conn.commit()

    def get_peer(self, router_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM peers WHERE router_id = ?", (router_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_peer_by_name(self, name: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM peers WHERE name = ?", (name,)
            ).fetchone()
            return dict(row) if row else None

    def list_peers(self, owner_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM peers WHERE owner_id = ? ORDER BY id", (owner_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def count_peers(self, owner_id: int) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM peers WHERE owner_id = ?", (owner_id,)
            ).fetchone()[0]

    def delete_peers_for_owner(self, owner_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM peers WHERE owner_id = ?", (owner_id,))
            self._conn.commit()

    def update_peer(self, router_id: str, **fields) -> None:
        keys = list(fields)
        with self._lock:
            self._conn.execute(
                "UPDATE peers SET "
                + ", ".join(f"{k} = ?" for k in keys)
                + " WHERE router_id = ?",
                [fields[k] for k in keys] + [router_id],
            )
            self._conn.commit()

    def delete_peer(self, router_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM peers WHERE router_id = ?", (router_id,))
            self._conn.commit()

    # --------------------------------------------------------------- settings
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def all_settings(self) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
            return {r["key"]: r["value"] for r in rows}
