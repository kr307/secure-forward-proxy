"""
Secure Forward Proxy - Admin Web Dashboard & Management API
Built with aiohttp for high-performance non-blocking administrative operations.
"""

import json
import logging
import os
from typing import Any, Dict
from aiohttp import web

from policy.engine import PolicyEngine
from storage.db import AuditDatabase

logger = logging.getLogger("ProxyDashboard")


class AdminDashboardApp:
    def __init__(self, config: Dict[str, Any], policy_engine: PolicyEngine, db: AuditDatabase, proxy_server=None):
        self.config = config
        self.policy_engine = policy_engine
        self.db = db
        self.proxy_server = proxy_server
        self.host = config.get("dashboard", {}).get("host", "0.0.0.0")
        self.port = int(config.get("dashboard", {}).get("port", 8081))

        self.app = web.Application()
        self._setup_routes()
        self.runner: web.AppRunner = None
        self.site: web.TCPSite = None

    def _setup_routes(self) -> None:
        self.app.router.add_get("/", self.handle_index)
        self.app.router.add_get("/api/stats", self.api_get_stats)
        self.app.router.add_get("/api/logs", self.api_get_logs)
        self.app.router.add_get("/api/rules", self.api_get_rules)
        self.app.router.add_post("/api/rules", self.api_add_rule)
        self.app.router.add_delete("/api/rules/{id}", self.api_delete_rule)
        self.app.router.add_post("/api/categories/{name}", self.api_toggle_category)
        self.app.router.add_post("/api/test-policy", self.api_test_policy)

    async def start(self) -> None:
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        logger.info(f"Admin Dashboard active at http://{self.host}:{self.port}")

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()
            logger.info("Admin Dashboard stopped.")

    async def handle_index(self, request: web.Request) -> web.Response:
        template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                html = f.read()
            return web.Response(text=html, content_type="text/html")
        return web.Response(text="Dashboard template not found.", status=404)

    async def api_get_stats(self, request: web.Request) -> web.Response:
        stats = self.db.get_metrics_summary()
        if self.proxy_server:
            stats["proxy_runtime"] = self.proxy_server.get_stats()
        return web.json_response(stats)

    async def api_get_logs(self, request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", 50))
        action_filter = request.query.get("action", None)
        logs = self.db.get_recent_logs(limit=limit, action_filter=action_filter)
        return web.json_response({"logs": logs})

    async def api_get_rules(self, request: web.Request) -> web.Response:
        rules = self.db.get_custom_rules()
        categories = []
        for name, default_action in self.policy_engine.category_actions.items():
            desc = self.policy_engine.category_descriptions.get(name, "")
            categories.append({
                "name": name,
                "action": default_action,
                "description": desc,
                "domain_count": sum(1 for c in self.policy_engine.category_domains.values() if c == name)
            })
        return web.json_response({"custom_rules": rules, "categories": categories})

    async def api_add_rule(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            pattern = data.get("pattern", "").strip()
            rule_type = data.get("rule_type", "exact")
            action = data.get("action", "BLOCK").upper()
            category = data.get("category", "custom")
            user_target = data.get("user_target", "GLOBAL")

            if not pattern:
                return web.json_response({"error": "Pattern is required"}, status=400)

            success = self.db.add_custom_rule(pattern, rule_type, action, category, user_target)
            if success:
                self.policy_engine.reload_from_db()
                return web.json_response({"status": "created", "pattern": pattern})
            return web.json_response({"error": "Rule pattern already exists"}, status=409)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_delete_rule(self, request: web.Request) -> web.Response:
        try:
            rule_id = int(request.match_info["id"])
            success = self.db.delete_custom_rule(rule_id)
            if success:
                self.policy_engine.reload_from_db()
                return web.json_response({"status": "deleted", "id": rule_id})
            return web.json_response({"error": "Rule not found"}, status=404)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_toggle_category(self, request: web.Request) -> web.Response:
        try:
            category_name = request.match_info["name"].strip().lower()
            data = await request.json()
            new_action = data.get("action", "BLOCK").upper()
            if new_action not in ("BLOCK", "ALLOW"):
                return web.json_response({"error": "Action must be BLOCK or ALLOW"}, status=400)

            self.db.set_category_action(category_name, new_action)
            self.policy_engine.reload_from_db()
            return web.json_response({"status": "updated", "category": category_name, "action": new_action})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def api_test_policy(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            host = data.get("host", "").strip()
            path = data.get("path", "")
            username = data.get("username", None)

            if not host:
                return web.json_response({"error": "Host is required"}, status=400)

            decision = self.policy_engine.evaluate(host, path, username)
            return web.json_response({
                "host": host,
                "action": decision.action,
                "category": decision.category,
                "rule_name": decision.rule_name,
                "reason": decision.reason
            })
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
