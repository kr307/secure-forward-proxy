"""
Secure Forward Proxy - Core Asyncio TCP Server
Manages client connection acceptance, concurrency throttling, and graceful lifecycle.
"""

import asyncio
import logging
from typing import Any, Dict, Optional, Set

from policy.engine import PolicyEngine
from proxy.handler import ProxyConnectionHandler
from storage.db import AuditDatabase

logger = logging.getLogger("ProxyServer")


class SecureForwardProxy:
    def __init__(self, config: Dict[str, Any], policy_engine: PolicyEngine, db: AuditDatabase):
        self.config = config
        self.policy_engine = policy_engine
        self.db = db
        self.host = config.get("proxy", {}).get("host", "0.0.0.0")
        self.port = int(config.get("proxy", {}).get("port", 8080))
        self.max_connections = int(config.get("proxy", {}).get("max_connections", 5000))

        self.handler = ProxyConnectionHandler(config, policy_engine, db)
        self.server: Optional[asyncio.Server] = None
        self.active_tasks: Set[asyncio.Task] = set()
        self.total_connections = 0
        self._running = False

    async def start(self) -> None:
        """Starts the TCP server listener."""
        self._running = True
        self.server = await asyncio.start_server(
            self._client_connected_cb,
            self.host,
            self.port,
            reuse_address=True
        )
        logger.info(f"Secure Forward Proxy running on {self.host}:{self.port}")

    async def _client_connected_cb(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._running:
            writer.close()
            return

        if len(self.active_tasks) >= self.max_connections:
            logger.warning("Max concurrent connections reached; rejecting connection.")
            writer.close()
            return

        self.total_connections += 1
        task = asyncio.create_task(self.handler.handle_connection(reader, writer))
        self.active_tasks.add(task)
        task.add_done_callback(self.active_tasks.discard)

    async def stop(self) -> None:
        """Gracefully closes server and waits for in-flight proxy connections to finish."""
        self._running = False
        logger.info("Stopping proxy server...")
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        if self.active_tasks:
            logger.info(f"Waiting for {len(self.active_tasks)} active connections to terminate...")
            # Cancel remaining tasks with short timeout
            for task in list(self.active_tasks):
                task.cancel()
            await asyncio.gather(*self.active_tasks, return_exceptions=True)
            self.active_tasks.clear()

        logger.info("Proxy server successfully stopped.")

    def get_stats(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "active_connections": len(self.active_tasks),
            "total_connections": self.total_connections,
            "running": self._running
        }
