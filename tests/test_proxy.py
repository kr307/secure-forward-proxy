"""
Integration tests for Secure Forward Proxy server.
"""

import asyncio
import os
import tempfile
import pytest

from policy.engine import PolicyEngine
from proxy.server import SecureForwardProxy
from storage.db import AuditDatabase


def get_proxy_env():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_proxy.db")
    db = AuditDatabase(db_path=db_path)

    config = {
        "proxy": {
            "host": "127.0.0.1",
            "port": 18080,
            "timeout": 5,
            "max_connections": 100,
            "buffer_size": 16384
        },
        "policy": {
            "default_action": "ALLOW",
            "enable_sni_sniffing": True,
            "categories_file": "config/categories.yaml"
        },
        "auth": {"enabled": False}
    }
    policy_engine = PolicyEngine(config, db)
    proxy_server = SecureForwardProxy(config, policy_engine, db)
    return proxy_server, db, config


def test_proxy_blocks_forbidden_domain_get():
    async def _run():
        proxy_server, db, config = get_proxy_env()
        await db.start()
        await proxy_server.start()

        try:
            # Open raw socket to proxy
            reader, writer = await asyncio.open_connection("127.0.0.1", 18080)
            # Send GET request for blacklisted domain facebook.com
            req = b"GET http://facebook.com/ HTTP/1.1\r\nHost: facebook.com\r\n\r\n"
            writer.write(req)
            await writer.drain()

            # Read response
            response = await reader.read(4096)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("iso-8859-1")
            assert "403 Forbidden" in response_str
            assert "X-Proxy-Action: BLOCKED" in response_str
            assert "social-media" in response_str
            assert "Access Blocked" in response_str

        finally:
            await proxy_server.stop()
            await db.stop()

    asyncio.run(_run())


def test_proxy_blocks_forbidden_connect():
    async def _run():
        proxy_server, db, config = get_proxy_env()
        await db.start()
        await proxy_server.start()

        try:
            # Open raw socket to proxy
            reader, writer = await asyncio.open_connection("127.0.0.1", 18080)
            # Send CONNECT request for blacklisted malware host
            req = b"CONNECT evil-c2-server.com:443 HTTP/1.1\r\nHost: evil-c2-server.com:443\r\n\r\n"
            writer.write(req)
            await writer.drain()

            response = await reader.read(4096)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("iso-8859-1")
            assert "403 Forbidden" in response_str
            assert "X-Proxy-Category: malware" in response_str

        finally:
            await proxy_server.stop()
            await db.stop()

    asyncio.run(_run())
