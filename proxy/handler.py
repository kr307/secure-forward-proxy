"""
Secure Forward Proxy - HTTP & HTTPS Connection Handler
Parses RFC 7230/7231 requests, enforces authentication, executes policy evaluation,
sniffs TLS SNI, serves professional block pages, and pipes established tunnels.
"""

import asyncio
import base64
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from policy.engine import PolicyDecision, PolicyEngine
from proxy.sni_parser import extract_sni_from_client_hello
from proxy.tunnel import TcpTunnel
from storage.db import AuditDatabase

logger = logging.getLogger("ProxyHandler")

BLOCK_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Corporate Security Policy</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --primary: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background-color: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            max-width: 620px;
            width: 100%;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .icon-badge {{
            width: 52px;
            height: 52px;
            border-radius: 12px;
            background: var(--danger-bg);
            border: 1px solid rgba(239, 68, 68, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--danger);
        }}
        .icon-badge svg {{ width: 28px; height: 28px; stroke: currentColor; fill: none; stroke-width: 2; }}
        h1 {{ font-size: 1.5rem; font-weight: 700; color: #fff; }}
        .subtitle {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 2px; }}
        .alert-box {{
            background: rgba(239, 68, 68, 0.08);
            border-left: 4px solid var(--danger);
            padding: 16px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 24px;
            font-size: 0.95rem;
            line-height: 1.5;
        }}
        .details-grid {{
            background: rgba(15, 23, 42, 0.6);
            border-radius: 12px;
            padding: 20px;
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 12px 16px;
            font-size: 0.88rem;
            margin-bottom: 28px;
            border: 1px solid var(--border);
        }}
        .label {{ color: var(--text-muted); font-weight: 500; }}
        .value {{ color: var(--text-main); font-family: monospace; word-break: break-all; }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            background: var(--danger-bg);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .footer {{
            border-top: 1px solid var(--border);
            padding-top: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="icon-badge">
                <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 8v4M12 16h.01"/></svg>
            </div>
            <div>
                <h1>Access Blocked</h1>
                <div class="subtitle">Secure Web Gateway Security Enforcement</div>
            </div>
        </div>

        <div class="alert-box">
            The request to this resource was blocked according to organizational security policy rules.
        </div>

        <div class="details-grid">
            <span class="label">Destination Host:</span>
            <span class="value">{host}</span>

            <span class="label">Security Category:</span>
            <span class="value"><span class="badge">{category}</span></span>

            <span class="label">Enforced Rule:</span>
            <span class="value">{rule}</span>

            <span class="label">Reason:</span>
            <span class="value">{reason}</span>

            <span class="label">Client IP:</span>
            <span class="value">{client_ip}</span>

            <span class="label">Timestamp:</span>
            <span class="value">{timestamp}</span>
        </div>

        <div class="footer">
            <span>Gateway ID: SWG-CORE-01</span>
            <span>If you believe this is an error, contact your IT Administrator.</span>
        </div>
    </div>
</body>
</html>
"""


class ProxyConnectionHandler:
    def __init__(self, config: Dict[str, Any], policy_engine: PolicyEngine, db: AuditDatabase):
        self.config = config
        self.policy_engine = policy_engine
        self.db = db
        self.tunnel = TcpTunnel(
            buffer_size=config.get("proxy", {}).get("buffer_size", 65536),
            idle_timeout=float(config.get("proxy", {}).get("timeout", 30))
        )
        self.auth_enabled = config.get("auth", {}).get("enabled", False)
        self.auth_users = config.get("auth", {}).get("users", {})
        self.enable_sni = config.get("policy", {}).get("enable_sni_sniffing", True)

    async def handle_connection(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        client_addr = client_writer.get_extra_info("peername")
        client_ip = client_addr[0] if client_addr else "127.0.0.1"
        start_time = time.time()
        username: Optional[str] = None
        method = "UNKNOWN"
        host = "unknown"
        port = 80
        uri = ""
        action = "ALLOW"
        category = "unclassified"
        rule_name = "default"
        bytes_sent = 0
        bytes_recv = 0

        try:
            # 1. Read initial HTTP request line
            request_line = await asyncio.wait_for(client_reader.readline(), timeout=10.0)
            if not request_line:
                return

            line_str = request_line.decode("iso-8859-1").strip()
            parts = line_str.split()
            if len(parts) < 2:
                return

            method = parts[0].upper()
            raw_target = parts[1]

            # 2. Read headers
            headers: Dict[str, str] = {}
            while True:
                header_line = await asyncio.wait_for(client_reader.readline(), timeout=10.0)
                if not header_line or header_line == b"\r\n" or header_line == b"\n":
                    break
                h_str = header_line.decode("iso-8859-1").strip()
                if ":" in h_str:
                    h_key, h_val = h_str.split(":", 1)
                    headers[h_key.strip().lower()] = h_val.strip()

            # 3. Authentication check
            if self.auth_enabled:
                auth_header = headers.get("proxy-authorization")
                auth_ok, username = self._check_auth(auth_header)
                if not auth_ok:
                    await self._send_auth_required(client_writer)
                    action = "BLOCK"
                    rule_name = "Auth Required"
                    category = "security"
                    return

            # 4. Resolve destination host and port
            if method == "CONNECT":
                # CONNECT target format: host:port
                if ":" in raw_target:
                    host, port_str = raw_target.split(":", 1)
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    host = raw_target
                    port = 443
                uri = raw_target
            else:
                # Regular HTTP: target can be full URL "http://example.com/foo" or relative with Host header
                if raw_target.startswith("http://") or raw_target.startswith("https://"):
                    parsed = urlparse(raw_target)
                    host = parsed.hostname or headers.get("host", "").split(":")[0]
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    uri = parsed.path or "/"
                    if parsed.query:
                        uri += f"?{parsed.query}"
                else:
                    host_header = headers.get("host", "")
                    if ":" in host_header:
                        host, port_str = host_header.split(":", 1)
                        port = int(port_str) if port_str.isdigit() else 80
                    else:
                        host = host_header or raw_target
                        port = 80
                    uri = raw_target

            # 5. Evaluate policy
            decision: PolicyDecision = self.policy_engine.evaluate(host, uri, username)
            action = decision.action
            category = decision.category
            rule_name = decision.rule_name

            if action == "BLOCK":
                await self._send_blocked_response(
                    client_writer,
                    method=method,
                    host=host,
                    category=category,
                    rule=rule_name,
                    reason=decision.reason,
                    client_ip=client_ip
                )
                return

            # 6. Dispatch proxying
            if method == "CONNECT":
                bytes_sent, bytes_recv = await self._handle_connect(
                    client_reader, client_writer, host, port, username, client_ip
                )
            else:
                bytes_sent, bytes_recv = await self._handle_http_forward(
                    client_reader, client_writer, method, host, port, uri, headers, request_line
                )

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug(f"Connection handling exception for {host}: {e}")
        finally:
            try:
                if not client_writer.is_closing():
                    client_writer.close()
                    await client_writer.wait_closed()
            except Exception:
                pass

            duration_ms = (time.time() - start_time) * 1000.0
            # Record audit log in async queue
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": client_ip,
                "username": username or "anonymous",
                "method": method,
                "host": host,
                "port": port,
                "uri": uri,
                "action": action,
                "category": category,
                "rule_name": rule_name,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_recv,
                "duration_ms": round(duration_ms, 2)
            }
            await self.db.log_request_async(log_entry)

    def _check_auth(self, auth_header: Optional[str]) -> Tuple[bool, Optional[str]]:
        if not auth_header or not auth_header.lower().startswith("basic "):
            return False, None
        try:
            cred_bytes = base64.b64decode(auth_header.split(" ", 1)[1])
            cred_str = cred_bytes.decode("utf-8")
            if ":" in cred_str:
                u, p = cred_str.split(":", 1)
                if self.auth_users.get(u) == p:
                    return True, u
        except Exception:
            pass
        return False, None

    async def _send_auth_required(self, writer: asyncio.StreamWriter) -> None:
        response = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic realm=\"Secure Forward Proxy\"\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 30\r\n\r\n"
            b"Proxy Authentication Required\r\n"
        )
        writer.write(response)
        await writer.drain()

    async def _send_blocked_response(
        self,
        writer: asyncio.StreamWriter,
        method: str,
        host: str,
        category: str,
        rule: str,
        reason: str,
        client_ip: str
    ) -> None:
        html_body = BLOCK_PAGE_TEMPLATE.format(
            host=host,
            category=category,
            rule=rule,
            reason=reason,
            client_ip=client_ip,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        ).encode("utf-8")

        response = (
            f"HTTP/1.1 403 Forbidden\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html_body)}\r\n"
            f"Connection: close\r\n"
            f"X-Proxy-Action: BLOCKED\r\n"
            f"X-Proxy-Category: {category}\r\n\r\n"
        ).encode("iso-8859-1") + html_body

        try:
            writer.write(response)
            await writer.drain()
        except Exception:
            pass

    async def _handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
        username: Optional[str],
        client_ip: str
    ) -> Tuple[int, int]:
        """Handles HTTPS tunneling with CONNECT method and TLS SNI inspection."""
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=15.0
            )
        except Exception as e:
            # Failed to connect to upstream server
            err_msg = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nCannot connect to {host}:{port}: {e}".encode("utf-8")
            client_writer.write(err_msg)
            await client_writer.drain()
            return 0, 0

        # Established connection to upstream! Send 200 Connection Established to client
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: SecureForwardProxy/1.0\r\n\r\n")
        await client_writer.drain()

        initial_client_chunk = b""

        # Inspect TLS SNI if enabled
        if self.enable_sni and port == 443:
            try:
                # Read the initial handshake packet
                initial_client_chunk = await asyncio.wait_for(client_reader.read(4096), timeout=5.0)
                if initial_client_chunk:
                    sni_host = extract_sni_from_client_hello(initial_client_chunk)
                    if sni_host:
                        # Evaluate SNI host against policy (detects domain fronting / mismatch)
                        sni_decision = self.policy_engine.evaluate(sni_host, "", username)
                        if sni_decision.action == "BLOCK":
                            logger.info(f"SNI filter blocked TLS connection to {sni_host} (requested {host})")
                            remote_writer.close()
                            # Tunnel is already raw TCP, so close connection
                            return len(initial_client_chunk), 0
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"SNI inspection error: {e}")

        # Pipe streams
        bytes_sent, bytes_recv = await self.tunnel.pipe(
            client_reader, client_writer, remote_reader, remote_writer, initial_client_chunk
        )

        try:
            remote_writer.close()
            await remote_writer.wait_closed()
        except Exception:
            pass

        return bytes_sent, bytes_recv

    async def _handle_http_forward(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        method: str,
        host: str,
        port: int,
        uri: str,
        headers: Dict[str, str],
        request_line: bytes
    ) -> Tuple[int, int]:
        """Forwards standard HTTP (GET, POST, etc.) requests."""
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=15.0
            )
        except Exception as e:
            err_msg = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nCannot connect to {host}:{port}: {e}".encode("utf-8")
            client_writer.write(err_msg)
            await client_writer.drain()
            return 0, 0

        # Rewrite request line with relative path if upstream expects standard HTTP format
        new_request_line = f"{method} {uri} HTTP/1.1\r\n".encode("iso-8859-1")
        remote_writer.write(new_request_line)

        # Forward headers, omitting proxy-specific headers
        hop_by_hop = {"proxy-connection", "proxy-authorization", "keep-alive"}
        for h_key, h_val in headers.items():
            if h_key not in hop_by_hop:
                remote_writer.write(f"{h_key.title()}: {h_val}\r\n".encode("iso-8859-1"))
        remote_writer.write(b"\r\n")
        await remote_writer.drain()

        # If request has body (e.g. POST), stream it to upstream
        content_length = int(headers.get("content-length", 0))
        if content_length > 0:
            body = await client_reader.readexactly(content_length)
            remote_writer.write(body)
            await remote_writer.drain()

        # Stream response back to client
        bytes_recv = 0
        while True:
            chunk = await remote_reader.read(65536)
            if not chunk:
                break
            client_writer.write(chunk)
            await client_writer.drain()
            bytes_recv += len(chunk)

        try:
            remote_writer.close()
            await remote_writer.wait_closed()
        except Exception:
            pass

        return content_length, bytes_recv
