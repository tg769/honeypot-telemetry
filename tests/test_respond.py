import dataclasses

from secu import respond
from secu.config import Settings


def _settings_with_allowlist(allowlist):
    return dataclasses.replace(respond.settings, responder_allowlist=allowlist, responder_max_rules=18)


def test_allowlisted_home_ip_never_ranked_even_at_max_score(monkeypatch, home_ip):
    monkeypatch.setattr(respond, "settings", _settings_with_allowlist([f"{home_ip}/32"]))

    scores = {home_ip: 999.0, "45.33.32.156": 10.0}
    candidates = respond.rank_candidates(scores)

    assert home_ip not in candidates
    assert "45.33.32.156" in candidates


def test_private_and_loopback_ips_always_excluded(monkeypatch):
    monkeypatch.setattr(respond, "settings", _settings_with_allowlist([]))

    scores = {"10.90.1.5": 500.0, "127.0.0.1": 500.0, "8.8.8.8": 5.0}
    candidates = respond.rank_candidates(scores)

    assert "10.90.1.5" not in candidates
    assert "127.0.0.1" not in candidates
    assert "8.8.8.8" in candidates


def test_reconcile_respects_rule_cap(monkeypatch):
    monkeypatch.setattr(respond, "settings", _settings_with_allowlist([]))
    respond.settings = dataclasses.replace(respond.settings, responder_max_rules=2)

    candidates = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    scores = {"1.1.1.1": 90, "2.2.2.2": 80, "3.3.3.3": 70}
    plan = respond.reconcile(candidates, scores)

    assert len(plan["to_add"]) == 2
    assert set(plan["to_add"]) == {"1.1.1.1", "2.2.2.2"}


def test_compute_scores_weights_successful_login_highest():
    findings = [
        {"rule_id": "BRUTE_FORCE", "src_ip": "1.1.1.1"},
        {"rule_id": "SUCCESSFUL_LOGIN", "src_ip": "2.2.2.2"},
    ]
    scores = respond.compute_scores(findings, {})
    assert scores["2.2.2.2"] > scores["1.1.1.1"]


def test_dry_run_never_persists_active_blocks(monkeypatch):
    # A dry-run's simulated "active" dict must never be saved. If it were,
    # a later --enforce run would read it back via reconcile() and think
    # those blocks already exist, so it would silently skip calling AWS
    # for any of them. This is exactly the bug that shipped once already.
    saved = {}
    monkeypatch.setattr(respond.statefile, "save", lambda name, value: saved.update({name: value}))
    monkeypatch.setattr(respond, "_audit", lambda *a, **kw: None)  # don't touch the real audit log

    plan = {"to_add": ["1.2.3.4"], "to_evict": [], "active_before": {}}
    respond.apply_plan(plan, {"1.2.3.4": 50}, enforce=False)

    assert "responder_blocks" not in saved


def test_rule_numbers_do_not_collide_with_aws_default_nacl_rule():
    # AWS's own default NACL uses rule number 100 for its built-in allow-all
    # rule. Trying to create a custom rule also numbered 100 fails with
    # NetworkAclEntryAlreadyExists, discovered by actually running --enforce
    # against a real NACL.
    active = {}
    first_assigned = respond._next_free_rule_number(active)
    assert first_assigned != 100


def test_enforce_calls_aws_and_persists_active_blocks(monkeypatch):
    saved = {}
    monkeypatch.setattr(respond.statefile, "save", lambda name, value: saved.update({name: value}))
    monkeypatch.setattr(respond, "_audit", lambda *a, **kw: None)  # don't touch the real audit log

    calls = []

    class FakeClient:
        def create_network_acl_entry(self, **kwargs):
            calls.append(kwargs)

    class FakeSession:
        def __init__(self, *a, **kw):
            pass

        def client(self, name):
            return FakeClient()

    monkeypatch.setattr("boto3.Session", FakeSession)

    plan = {"to_add": ["1.2.3.4"], "to_evict": [], "active_before": {}}
    respond.apply_plan(plan, {"1.2.3.4": 50}, enforce=True)

    assert len(calls) == 1
    assert calls[0]["CidrBlock"] == "1.2.3.4/32"
    assert "responder_blocks" in saved
    assert "1.2.3.4" in saved["responder_blocks"]
