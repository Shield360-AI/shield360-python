"""Guard decisions are reported to Shield360 when a URL and key are set."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from shield360.guard import _report
from shield360.guard._pipeline import Pipeline
from shield360.guard.pii import PII


class _Platform(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Platform.received.append({"auth": self.headers.get("Authorization"), "path": self.path, "body": body})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")


def _serve():
    server = HTTPServer(("127.0.0.1", 0), _Platform)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_reports_decisions_but_never_the_text():
    _Platform.received.clear()
    server = _serve()
    try:
        assert _report.configure(
            f"http://127.0.0.1:{server.server_port}", "key-1", application_name="hr-assistant", environment="test"
        )
        pipeline = Pipeline(guards=[PII(action="redact")])
        pipeline.evaluate("SSN 123-45-6789", phase="preflight")
        pipeline.evaluate("nothing to see", phase="preflight")  # allow: not reported
        _report.flush()

        events = [e for r in _Platform.received for e in r["body"]["events"]]
        assert len(events) == 1
        attrs = events[0]["attrs"]
        assert events[0]["name"] == "shield360.guard.decision"
        assert attrs["shield360.guard.action"] == "redact"
        assert attrs["shield360.guard.kinds"] == "ssn"
        assert attrs["shield360.guard.target"] == "preflight"
        assert attrs["shield360.guard.client"] == "hr-assistant"
        assert attrs["shield360.guard.app"] == "hr-assistant"
        assert _Platform.received[0]["body"]["resource"]["service.name"] == "hr-assistant"
        assert _Platform.received[0]["auth"] == "Bearer key-1"
        assert _Platform.received[0]["path"] == "/api/guard/events"
        assert "123-45-6789" not in json.dumps(_Platform.received)
    finally:
        _report._reporter.close()  # pylint: disable=protected-access
        _report._reporter = None  # pylint: disable=protected-access
        server.shutdown()


def test_nothing_is_reported_without_a_url_and_key():
    assert not _report.configure(None, "key", application_name="a", environment="e")
    assert not _report.configure("http://x", None, application_name="a", environment="e")
    _report.report("pii", "deny", "ssn", "preflight")  # no reporter: a no-op
