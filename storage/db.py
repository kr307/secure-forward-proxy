"""
Secure Forward Proxy - Database & Audit Storage Engine
Handles SQLite initialization, asynchronous log batching, rule persistence, and analytical queries.
"""

import asyncio
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AuditDatabase:
    def __init__(self, db_path: str = "data/proxy_audit.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()
        self._log_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Table for real-time audit logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    username TEXT,
                    method TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    uri TEXT,
                    action TEXT NOT NULL,
                    category TEXT,
                    rule_name TEXT,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    duration_ms REAL DEFAULT 0.0
                )
            """)

            # Table for custom policies/rules added via Dashboard/API
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT NOT NULL UNIQUE,
                    rule_type TEXT NOT NULL, -- exact, wildcard, regex
                    action TEXT NOT NULL,    -- BLOCK, ALLOW
                    category TEXT DEFAULT 'custom',
                    user_target TEXT DEFAULT 'GLOBAL',
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)

            # Table for category-level enforcement toggles
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS category_toggles (
                    category_name TEXT PRIMARY KEY,
                    action TEXT NOT NULL, -- BLOCK, ALLOW
                    enabled INTEGER DEFAULT 1
                )
            """)

            # Indexes for ultra-fast query performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs (timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_action ON access_logs (action)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_host ON access_logs (host)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_category ON access_logs (category)")
            conn.commit()

    async def start(self) -> None:
        """Starts background batch writer task."""
        self._running = True
        self._worker_task = asyncio.create_task(self._batch_writer())

    async def stop(self) -> None:
        """Flushes queue and gracefully shuts down."""
        self._running = False
        if self._worker_task:
            await self._log_queue.join()
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def log_request_async(self, entry: Dict[str, Any]) -> None:
        """Enqueues access log without blocking proxy worker thread."""
        try:
            self._log_queue.put_nowait(entry)
        except asyncio.QueueFull:
            pass  # Drop under catastrophic load to preserve proxy availability

    async def _batch_writer(self) -> None:
        """Consumes logs from queue and batches into SQLite transactions."""
        while self._running:
            batch = []
            try:
                # Wait for at least one item
                item = await asyncio.wait_for(self._log_queue.get(), timeout=1.0)
                batch.append(item)
                self._log_queue.task_done()

                # Drain more if available (up to 100)
                while len(batch) < 100:
                    try:
                        next_item = self._log_queue.get_nowait()
                        batch.append(next_item)
                        self._log_queue.task_done()
                    except asyncio.QueueEmpty:
                        break

            except asyncio.TimeoutError:
                continue

            if batch:
                await asyncio.to_thread(self._write_batch_sync, batch)

    def _write_batch_sync(self, batch: List[Dict[str, Any]]) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO access_logs (
                    timestamp, client_ip, username, method, host, port, uri,
                    action, category, rule_name, bytes_sent, bytes_received, duration_ms
                ) VALUES (
                    :timestamp, :client_ip, :username, :method, :host, :port, :uri,
                    :action, :category, :rule_name, :bytes_sent, :bytes_received, :duration_ms
                )
            """, batch)
            conn.commit()

    def get_recent_logs(self, limit: int = 50, offset: int = 0, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM access_logs"
            params = []
            if action_filter and action_filter.upper() in ("BLOCK", "ALLOW"):
                query += " WHERE action = ?"
                params.append(action_filter.upper())
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Calculates security metrics for real-time dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Total and action breakdown
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
                    SUM(bytes_sent + bytes_received) as total_bytes
                FROM access_logs
            """)
            counts = cursor.fetchone()
            total = counts["total"] or 0
            blocked = counts["blocked"] or 0
            allowed = counts["allowed"] or 0
            total_bytes = counts["total_bytes"] or 0

            # Top blocked domains
            cursor.execute("""
                SELECT host, COUNT(*) as count 
                FROM access_logs 
                WHERE action = 'BLOCK' 
                GROUP BY host 
                ORDER BY count DESC 
                LIMIT 5
            """)
            top_blocked = [dict(row) for row in cursor.fetchall()]

            # Category distribution
            cursor.execute("""
                SELECT COALESCE(category, 'unclassified') as category, COUNT(*) as count 
                FROM access_logs 
                GROUP BY category 
                ORDER BY count DESC 
                LIMIT 6
            """)
            categories = [dict(row) for row in cursor.fetchall()]

            # Requests in last 24h
            cursor.execute("""
                SELECT COUNT(*) as count_24h
                FROM access_logs
                WHERE timestamp >= datetime('now', '-1 day')
            """)
            row_24h = cursor.fetchone()
            count_24h = row_24h["count_24h"] if row_24h else 0

            return {
                "total_requests": total,
                "blocked_requests": blocked,
                "allowed_requests": allowed,
                "block_rate": round((blocked / total * 100), 2) if total > 0 else 0.0,
                "total_bytes": total_bytes,
                "requests_last_24h": count_24h,
                "top_blocked_domains": top_blocked,
                "category_distribution": categories
            }

    # Policy rules operations
    def get_custom_rules(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM custom_rules ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def add_custom_rule(self, pattern: str, rule_type: str, action: str, category: str = "custom", user_target: str = "GLOBAL") -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO custom_rules (pattern, rule_type, action, category, user_target, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                """, (pattern.strip().lower(), rule_type, action.upper(), category, user_target, datetime.now(timezone.utc).isoformat()))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def delete_custom_rule(self, rule_id: int) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_category_toggles(self) -> Dict[str, str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT category_name, action, enabled FROM category_toggles WHERE enabled = 1")
            return {row["category_name"]: row["action"] for row in cursor.fetchall()}

    def set_category_action(self, category_name: str, action: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO category_toggles (category_name, action, enabled)
                VALUES (?, ?, 1)
                ON CONFLICT(category_name) DO UPDATE SET action = excluded.action, enabled = 1
            """, (category_name, action.upper()))
            conn.commit()
