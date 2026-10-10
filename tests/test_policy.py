"""
Unit tests for Policy and URL Filtering Engine.
"""

import os
import tempfile
import pytest

from policy.engine import PolicyEngine
from storage.db import AuditDatabase


@pytest.fixture
def policy_setup():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_audit.db")
    db = AuditDatabase(db_path=db_path)

    config = {
        "policy": {
            "default_action": "ALLOW",
            "categories_file": "config/categories.yaml"
        }
    }
    engine = PolicyEngine(config, db)
    yield engine, db


def test_category_block(policy_setup):
    engine, db = policy_setup
    decision = engine.evaluate("facebook.com")
    assert decision.action == "BLOCK"
    assert decision.category == "social-media"


def test_category_subdomain_inheritance(policy_setup):
    engine, db = policy_setup
    decision = engine.evaluate("static.xx.fbcdn.net")  # Should be unclassified or allowed unless defined
    decision_sub = engine.evaluate("m.facebook.com")
    assert decision_sub.action == "BLOCK"
    assert decision_sub.category == "social-media"


def test_category_allow(policy_setup):
    engine, db = policy_setup
    decision = engine.evaluate("bbc.com")
    assert decision.action == "ALLOW"
    assert decision.category == "news"


def test_custom_wildcard_rule(policy_setup):
    engine, db = policy_setup
    # Add wildcard rule into DB
    db.add_custom_rule("*.internal-leaks.org", "wildcard", "BLOCK", category="data-loss")
    engine.reload_from_db()

    decision = engine.evaluate("topsecret.internal-leaks.org")
    assert decision.action == "BLOCK"
    assert "Wildcard" in decision.rule_name


def test_custom_exact_rule(policy_setup):
    engine, db = policy_setup
    db.add_custom_rule("mybadsite.com", "exact", "BLOCK", category="custom-test")
    engine.reload_from_db()

    decision = engine.evaluate("mybadsite.com")
    assert decision.action == "BLOCK"


def test_default_allow_fallback(policy_setup):
    engine, db = policy_setup
    decision = engine.evaluate("random-clean-site-xyz-123.org")
    assert decision.action == "ALLOW"
    assert decision.category == "unclassified"
