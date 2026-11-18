"""The guard heartbeat says which guards run, in which mode, and nothing else."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from shield360.guard import _heartbeat, _report
from shield360.guard.pii import PII
from shield360.guard.prompt_injection import PromptInjection


class _Platform(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        _Platform.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")


def _serve():
    server = HTTPServer(("127.0.0.1", 0), _Platform)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _events():
    return [e for body in _Platform.received for e in body["events"]]


def test_modes_per_kind_strongest_first():
    modes = _heartbeat.guard_modes([PII(action="warn"), PII(action="redact"), PromptInjection(action="allow")])
    assert modes == {"pii": "block", "prompt_injection": "off"}
    attrs = _heartbeat.heartbeat_attrs([PromptInjection(action="deny")], "support-bot", "1.2.3")
    assert attrs == {
        "shield360.guard.app": "support-bot",
        "shield360.guard.modes": '{"prompt_injection":"block"}',
        "shield360.guard.injection": "true",
        "shield360.sdk.name": "shield360-python",
        "shield360.sdk.version": "1.2.3",
    }


def test_beats_once_at_start_without_content_host_or_user():
    _Platform.received.clear()
    server = _serve()
    try:
        assert _report.configure(
            f"http://127.0.0.1:{server.server_port}", "k", application_name="support-bot", environment="prod",
            sdk_version="1.2.3", guards=[PII(action="redact")],
        )
        for _ in range(50):
            _report.flush()
            if _events():
                break
            threading.Event().wait(0.02)
        events = _events()
        assert len(events) == 1
        assert events[0]["name"] == "shield360.guard.heartbeat"
        assert events[0]["attrs"]["shield360.guard.modes"] == '{"pii":"block"}'
        assert sorted(events[0]["attrs"]) == [
            "shield360.guard.app", "shield360.guard.injection", "shield360.guard.modes", "shield360.sdk.name", "shield360.sdk.version",
        ]
    finally:
        _report._reporter.close()  # pylint: disable=protected-access
        _report._reporter = None  # pylint: disable=protected-access
        server.shutdown()


def test_off_without_guards_with_the_option_or_the_environment():
    _Platform.received.clear()
    server = _serve()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        _report.configure(url, "k", application_name="a", environment="e")
        _report.configure(url, "k", application_name="a", environment="e", guards=[PII()], heartbeat=False)
        _report.flush()
        assert _events() == []
    finally:
        _report._reporter.close()  # pylint: disable=protected-access
        _report._reporter = None  # pylint: disable=protected-access
        server.shutdown()
    assert _heartbeat.heartbeat_enabled(None, {"SHIELD360_GUARD_HEARTBEAT": "false"}) is False
    assert _heartbeat.heartbeat_enabled(None, {}) is True


def test_jittered_interval():
    assert _heartbeat.next_delay(lambda: 0) == 240
    assert _heartbeat.next_delay(lambda: 1) == 360
