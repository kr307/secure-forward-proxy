"""
Secure Forward Proxy & URL Filtering Engine (Aegis Gate SWG)
Unified entry point launching the forward proxy server and web management dashboard.
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import yaml

from dashboard.app import AdminDashboardApp
from policy.engine import PolicyEngine
from proxy.server import SecureForwardProxy
from storage.db import AuditDatabase


def setup_logging(level_name: str = "INFO") -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def load_config(config_path: str) -> dict:
    default_config = {
        "proxy": {"host": "0.0.0.0", "port": 8080, "timeout": 30, "max_connections": 5000, "buffer_size": 65536},
        "dashboard": {"enabled": True, "host": "0.0.0.0", "port": 8081},
        "storage": {"db_path": "data/proxy_audit.db"},
        "policy": {"default_action": "ALLOW", "enable_sni_sniffing": True, "categories_file": "config/categories.yaml"},
        "auth": {"enabled": False, "users": {}},
        "logging": {"level": "INFO"}
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_conf = yaml.safe_load(f) or {}
                for k, v in user_conf.items():
                    if isinstance(v, dict) and k in default_config:
                        default_config[k].update(v)
                    else:
                        default_config[k] = v
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
    return default_config


async def run_services(config: dict, disable_dashboard: bool = False):
    db = AuditDatabase(db_path=config.get("storage", {}).get("db_path", "data/proxy_audit.db"))
    await db.start()

    policy_engine = PolicyEngine(config, db)
    proxy_server = SecureForwardProxy(config, policy_engine, db)
    await proxy_server.start()

    dashboard_app = None
    if config.get("dashboard", {}).get("enabled", True) and not disable_dashboard:
        dashboard_app = AdminDashboardApp(config, policy_engine, db, proxy_server)
        await dashboard_app.start()

    banner = f"""
========================================================================
    AEGIS GATE - SECURE FORWARD PROXY & URL FILTERING GATEWAY
========================================================================
  [+] Proxy Server:     http://{config['proxy']['host']}:{config['proxy']['port']}
  [+] Admin Dashboard:  http://localhost:{config['dashboard']['port']}
  [+] Storage Engine:   {config['storage']['db_path']}
  [+] SNI Inspection:   {'ENABLED' if config['policy']['enable_sni_sniffing'] else 'DISABLED'}
  [+] Auth Enforcement: {'ENABLED' if config['auth']['enabled'] else 'DISABLED'}
------------------------------------------------------------------------
  Press Ctrl+C to terminate cleanly.
========================================================================
"""
    print(banner)

    stop_event = asyncio.Event()

    def _signal_handler():
        print("\nShutdown signal received. Initiating graceful shutdown...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, _signal_handler)

    try:
        if sys.platform == "win32":
            # On Windows, wait with a sleep loop to catch KeyboardInterrupt cleanly
            while not stop_event.is_set():
                await asyncio.sleep(0.5)
        else:
            await stop_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        print("\nStopping services...")
        if dashboard_app:
            await dashboard_app.stop()
        await proxy_server.stop()
        await db.stop()
        print("Aegis Gate shutdown complete.")


def main():
    parser = argparse.ArgumentParser(description="Aegis Gate - Secure Forward Proxy with URL Filtering")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    parser.add_argument("--port", type=int, help="Override proxy port (default: 8080)")
    parser.add_argument("--dashboard-port", type=int, help="Override dashboard port (default: 8081)")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable web dashboard")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.port:
        config["proxy"]["port"] = args.port
    if args.dashboard_port:
        config["dashboard"]["port"] = args.dashboard_port
    if args.log_level:
        config["logging"]["level"] = args.log_level

    setup_logging(config["logging"]["level"])

    try:
        asyncio.run(run_services(config, disable_dashboard=args.no_dashboard))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
