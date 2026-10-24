import sqlite3
import logging
import contextlib
from pathlib import Path
from typing import Optional, List, Dict, Any, Generator

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Stateful persistence layer for Enterprise Configuration Auditing,
    utilizing MAC-keyed host identity and playbook execution tracking.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @contextlib.contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yields a configured SQLite connection with foreign key support."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        """Initializes the database schema with MAC-centric architecture."""
        schema = """
        CREATE TABLE IF NOT EXISTS hosts (
            mac_address TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL,
            hostname TEXT,
            os_info TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service_name TEXT,
            banner TEXT,
            state TEXT DEFAULT 'open',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(mac_address, port, protocol),
            FOREIGN KEY (mac_address) REFERENCES hosts(mac_address) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_execution_history (
            mac_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            playbook_id TEXT NOT NULL,
            status TEXT NOT NULL,
            attempts INTEGER DEFAULT 1,
            execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (mac_address, port, playbook_id),
            FOREIGN KEY (mac_address) REFERENCES hosts(mac_address) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            command TEXT,
            status TEXT,
            target TEXT
        );

        CREATE TABLE IF NOT EXISTS agent_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            phase TEXT,
            error TEXT,
            timestamp REAL
        );
        """
        try:
            with self._get_connection() as conn:
                conn.executescript(schema)
                conn.commit()
            logger.debug("Database schema initialized successfully.")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize schema: {e}")
            raise

    def upsert_host(
        self, 
        mac_address: str, 
        ip_address: str, 
        hostname: Optional[str] = None, 
        os_info: Optional[str] = None
    ) -> None:
        """
        Registers or updates a host. The IP address is treated as mutable,
        allowing the system to track hosts across DHCP lease changes.
        """
        query = """
        INSERT INTO hosts (mac_address, ip_address, hostname, os_info, last_seen)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(mac_address) DO UPDATE SET
            ip_address = excluded.ip_address,
            hostname = COALESCE(excluded.hostname, hosts.hostname),
            os_info = COALESCE(excluded.os_info, hosts.os_info),
            last_seen = CURRENT_TIMESTAMP;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(query, (mac_address, ip_address, hostname, os_info))
                conn.commit()
            logger.info(f"Upserted host {mac_address} at {ip_address}")
        except sqlite3.Error as e:
            logger.error(f"Error upserting host {mac_address}: {e}")
            raise

    def upsert_service(
        self,
        mac_address: str,
        port: int,
        protocol: str = "tcp",
        service_name: Optional[str] = None,
        banner: Optional[str] = None,
        state: str = "open"
    ) -> None:
        """Registers or updates a discovered network service on a specific host."""
        query = """
        INSERT INTO services (mac_address, port, protocol, service_name, banner, state, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(mac_address, port, protocol) DO UPDATE SET
            service_name = COALESCE(excluded.service_name, services.service_name),
            banner = COALESCE(excluded.banner, services.banner),
            state = excluded.state,
            last_seen = CURRENT_TIMESTAMP;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(query, (mac_address, port, protocol, service_name, banner, state))
                conn.commit()
            logger.debug(f"Upserted service {port}/{protocol} for {mac_address}")
        except sqlite3.Error as e:
            logger.error(f"Error upserting service for {mac_address} on {port}: {e}")
            raise

    def record_playbook_execution(
        self, 
        mac_address: str, 
        port: int, 
        playbook_id: str, 
        status: str = "completed",
        max_attempts: int = 3
    ) -> None:
        """
        Logs the execution state of an audit playbook against a specific target
        to prevent redundant verification cycles.

        Retries a 'failed' playbook on subsequent cycles (has_playbook_run
        stays False) up to max_attempts — after that, status is forced to
        'completed' regardless of the real outcome, purely to stop it
        retrying forever. Without this cap, a playbook whose underlying
        tool legitimately exits non-zero on every attempt (a common case —
        e.g. a failed default-credential check) would run every single
        enumeration cycle indefinitely.
        """
        query = """
        INSERT INTO audit_execution_history (mac_address, port, playbook_id, status, attempts, execution_time)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(mac_address, port, playbook_id) DO UPDATE SET
            status = CASE
                WHEN excluded.status = 'completed' OR excluded.status = 'verified' THEN excluded.status
                WHEN audit_execution_history.attempts + 1 >= ? THEN 'completed'
                ELSE excluded.status
            END,
            attempts = audit_execution_history.attempts + 1,
            execution_time = CURRENT_TIMESTAMP;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(query, (mac_address, port, playbook_id, status, max_attempts))
                conn.commit()
            logger.info(f"Recorded playbook '{playbook_id}' execution for {mac_address}:{port} as {status}")
        except sqlite3.Error as e:
            logger.error(f"Error recording playbook execution for {mac_address}:{port}: {e}")
            raise

    def has_playbook_run(self, mac_address: str, port: int, playbook_id: str) -> bool:
        """Queries whether a specific playbook has already been completed for a target."""
        query = """
        SELECT status FROM audit_execution_history 
        WHERE mac_address = ? AND port = ? AND playbook_id = ?
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query, (mac_address, port, playbook_id))
                row = cursor.fetchone()
                if row and row["status"] in ("completed", "verified"):
                    return True
                return False
        except sqlite3.Error as e:
            logger.error(f"Error checking playbook execution history: {e}")
            return False

    def get_exhausted_playbook_ids(self, mac_address: str, port: int) -> List[str]:
        """All playbook_ids already completed/verified for this exact
        (host, port) — for PlaybookLoader's exclude_ids, so it stops
        suggesting a playbook that's already done, up front, rather than
        only recording the outcome after re-selecting it again."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT playbook_id FROM audit_execution_history "
                "WHERE mac_address = ? AND port = ? AND status IN ('completed', 'verified')",
                (mac_address, port)
            )
            return [row["playbook_id"] for row in cursor.fetchall()]

    def record_audit(self, command: List[str], status: str, target: str, timestamp: Optional[float] = None) -> None:
        """Record that a command was executed, for the /api/summary count and
        the /api/logs/stream Live Audit Log panel. `command` is stored as a
        single shell-like string for readability; `status` should be a short
        label ('ok', 'failed', 'timeout', etc.); `target` is typically 'ip:port'."""
        import time
        if timestamp is None:
            timestamp = time.time()
        command_str = " ".join(str(c) for c in command)
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO audit_logs (timestamp, command, status, target) VALUES (?, ?, ?, ?)",
                (timestamp, command_str, status, target)
            )
            conn.commit()

    def get_logs(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT timestamp, command, status, target FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
            return [dict(row) for row in cursor.fetchall()]

    def upsert_state(self, state_data: Dict[str, Any]) -> None:
        import time
        phase = state_data.get("phase", "INITIALIZATION")
        error = state_data.get("error", "")
        ts = state_data.get("timestamp", time.time())
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO agent_state (id, phase, error, timestamp)
                VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                phase=excluded.phase, error=excluded.error, timestamp=excluded.timestamp
            """, (phase, error, ts))
            conn.commit()

    def get_state(self) -> Dict[str, Any]:
        """Read back the agent's current phase/error, written by
        upsert_state(). Powers /api/health."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT phase, error, timestamp FROM agent_state WHERE id = 1").fetchone()
            if not row:
                return {"phase": "UNKNOWN", "error": "", "timestamp": 0.0}
            return {"phase": row["phase"] or "UNKNOWN", "error": row["error"] or "", "timestamp": row["timestamp"] or 0.0}

    def get_summary(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            hosts = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            services = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
            commands = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        return {"total_hosts": hosts, "total_services": services, "total_commands": commands}

    def get_hosts(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Returns hosts in the shape the dashboard/API/report expect
        (ip_address-keyed view), built from the underlying MAC-keyed
        schema. A host's MAC is included so callers can track identity
        across IP changes; a synthetic 'ip:<address>' key (see
        _resolve_mac_key) means no real MAC was ever resolved for it
        (e.g. loopback) and is not shown as a real MAC here."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT mac_address, ip_address, os_info FROM hosts LIMIT ? OFFSET ?", (limit, offset)
            )
            hosts = []
            for row in cursor.fetchall():
                mac = row["mac_address"]
                svc_cursor = conn.execute(
                    "SELECT port, protocol, service_name, banner FROM services WHERE mac_address = ?", (mac,)
                )
                services = [dict(s) for s in svc_cursor.fetchall()]
                hosts.append({
                    "ip_address": row["ip_address"],
                    "mac_address": "" if mac.startswith("ip:") else mac,
                    "os_guess": row["os_info"] or "Unknown",
                    "status": "active",
                    "services": services
                })
            return hosts

    def get_pending_targets(self) -> List[Dict[str, Any]]:
        """Hosts + their services, in the shape orchestrator's enumeration
        loop iterates over. Keyed internally by MAC (or the synthetic
        'ip:<address>' fallback) but exposes ip_address/mac_address for
        the caller, since commands target an IP."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT mac_address, ip_address FROM hosts")
            targets = []
            for row in cursor.fetchall():
                mac = row["mac_address"]
                svc_cursor = conn.execute(
                    "SELECT port, protocol, service_name, banner FROM services WHERE mac_address = ?", (mac,)
                )
                services = [dict(s) for s in svc_cursor.fetchall()]
                targets.append({
                    "ip_address": row["ip_address"],
                    "mac_address": mac,
                    "services": services
                })
            return targets

    @staticmethod
    def resolve_mac_key(ip_address: str, mac_address: Optional[str]) -> str:
        """mac_address is this schema's primary key, but not every host
        resolves a real one (loopback, or a device reached through a
        router hop that never responds to ARP). Falls back to a stable
        synthetic key derived from the IP so such hosts can still be
        tracked, rather than being silently dropped (upsert_host requires
        a non-null mac_address)."""
        return mac_address.lower() if mac_address else f"ip:{ip_address}"

    def close(self) -> None:
        pass
