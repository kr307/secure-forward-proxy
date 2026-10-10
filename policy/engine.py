"""
Secure Forward Proxy - Policy & URL Filtering Engine
Evaluates domains, URLs, and users against Threat Intelligence categories,
wildcards, regexes, and database-managed policies.
"""

import fnmatch
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
import yaml

from storage.db import AuditDatabase

logger = logging.getLogger("ProxyPolicy")


@dataclass
class PolicyDecision:
    action: str          # "ALLOW" or "BLOCK"
    category: str        # e.g., "social-media", "malware", "custom", "default"
    rule_name: str       # identifier or matched pattern
    reason: str          # explanation for audit log and block page


class PolicyEngine:
    def __init__(self, config: Dict[str, Any], db: AuditDatabase):
        self.config = config
        self.db = db
        self.default_action = config.get("policy", {}).get("default_action", "ALLOW").upper()
        self.categories_file = config.get("policy", {}).get("categories_file", "config/categories.yaml")

        # In-memory fast lookups
        self.category_domains: Dict[str, str] = {}  # domain -> category_name
        self.category_actions: Dict[str, str] = {}  # category_name -> "BLOCK" | "ALLOW"
        self.category_descriptions: Dict[str, str] = {}

        self.custom_exact_rules: Dict[str, Dict[str, Any]] = {}  # domain -> rule dict
        self.custom_wildcards: List[Dict[str, Any]] = []          # list of wildcard rules
        self.custom_regexes: List[Dict[str, Any]] = []            # list of compiled regex rules

        self.load_categories()
        self.reload_from_db()

    def load_categories(self) -> None:
        """Loads static categorized threat intel lists from YAML file."""
        if not os.path.exists(self.categories_file):
            logger.warning(f"Categories file not found: {self.categories_file}")
            return

        try:
            with open(self.categories_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            categories = data.get("categories", {})
            for cat_name, cat_data in categories.items():
                action = cat_data.get("action", "BLOCK").upper()
                desc = cat_data.get("description", "")
                self.category_actions[cat_name] = action
                self.category_descriptions[cat_name] = desc

                domains = cat_data.get("domains", [])
                for d in domains:
                    norm = d.strip().lower()
                    self.category_domains[norm] = cat_name
                    # Also register root if starts with www. or vice versa
                    if norm.startswith("www."):
                        self.category_domains[norm[4:]] = cat_name

            logger.info(f"Loaded {len(categories)} categories and {len(self.category_domains)} threat domains")
        except Exception as e:
            logger.error(f"Error loading categories: {e}")

    def reload_from_db(self) -> None:
        """Pulls dynamic overrides and custom rules from SQLite."""
        try:
            # 1. Update category actions from dynamic overrides
            overrides = self.db.get_category_toggles()
            for cat_name, action in overrides.items():
                self.category_actions[cat_name] = action

            # 2. Rebuild custom rule tables
            self.custom_exact_rules.clear()
            self.custom_wildcards.clear()
            self.custom_regexes.clear()

            db_rules = self.db.get_custom_rules()
            for r in db_rules:
                if not r.get("enabled", 1):
                    continue

                pattern = r["pattern"].strip().lower()
                rule_type = r.get("rule_type", "exact").lower()

                if rule_type == "exact":
                    self.custom_exact_rules[pattern] = r
                elif rule_type == "wildcard":
                    self.custom_wildcards.append(r)
                elif rule_type == "regex":
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE)
                        self.custom_regexes.append({"compiled": compiled, **r})
                    except re.error as err:
                        logger.error(f"Invalid regex rule pattern '{pattern}': {err}")

            logger.debug("Policy engine successfully synced rules from database.")
        except Exception as e:
            logger.error(f"Failed to reload policy rules from database: {e}")

    def evaluate(self, host: str, path: str = "", username: Optional[str] = None) -> PolicyDecision:
        """
        Evaluates a request against the policy pipeline:
        1. User-specific custom rules
        2. Custom Exact & Wildcard rules (Global)
        3. Category database
        4. Default Action
        """
        normalized_host = host.split(":")[0].strip().lower()
        full_target = f"{normalized_host}{path}" if path else normalized_host

        # --- Rule Phase 1: Per-User / Global Custom Exact Rules ---
        if normalized_host in self.custom_exact_rules:
            rule = self.custom_exact_rules[normalized_host]
            user_target = rule.get("user_target", "GLOBAL")
            if user_target == "GLOBAL" or (username and username.lower() == user_target.lower()):
                action = rule["action"].upper()
                return PolicyDecision(
                    action=action,
                    category=rule.get("category", "custom"),
                    rule_name=f"Exact rule: {normalized_host}",
                    reason=f"Matched custom exact rule for {normalized_host}"
                )

        # --- Rule Phase 2: Custom Wildcard Rules ---
        for r in self.custom_wildcards:
            user_target = r.get("user_target", "GLOBAL")
            if user_target != "GLOBAL" and (not username or username.lower() != user_target.lower()):
                continue

            pat = r["pattern"]
            # Match domain or subdomains
            if fnmatch.fnmatch(normalized_host, pat) or fnmatch.fnmatch(normalized_host, f"*.{pat.lstrip('*.')}"):
                return PolicyDecision(
                    action=r["action"].upper(),
                    category=r.get("category", "custom"),
                    rule_name=f"Wildcard rule: {pat}",
                    reason=f"Matched custom wildcard pattern '{pat}'"
                )

        # --- Rule Phase 3: Custom Regex Rules ---
        for r in self.custom_regexes:
            user_target = r.get("user_target", "GLOBAL")
            if user_target != "GLOBAL" and (not username or username.lower() != user_target.lower()):
                continue

            if r["compiled"].search(full_target):
                return PolicyDecision(
                    action=r["action"].upper(),
                    category=r.get("category", "custom"),
                    rule_name=f"Regex rule: {r['pattern']}",
                    reason=f"Matched custom regex rule '{r['pattern']}'"
                )

        # --- Rule Phase 4: Category Database Match ---
        # Direct lookup
        category = self.category_domains.get(normalized_host)

        # If not exact, check parent domain (e.g. graph.facebook.com -> facebook.com)
        if not category:
            parts = normalized_host.split(".")
            for i in range(1, len(parts) - 1):
                parent_domain = ".".join(parts[i:])
                if parent_domain in self.category_domains:
                    category = self.category_domains[parent_domain]
                    break

        if category:
            action = self.category_actions.get(category, "ALLOW").upper()
            desc = self.category_descriptions.get(category, "")
            return PolicyDecision(
                action=action,
                category=category,
                rule_name=f"Category: {category}",
                reason=f"Domain belongs to category '{category}' ({desc or 'policy controlled'})"
            )

        # --- Rule Phase 5: Default Fallback Action ---
        return PolicyDecision(
            action=self.default_action,
            category="unclassified",
            rule_name="Default Policy",
            reason=f"No blocking rules matched; applied default action {self.default_action}"
        )
