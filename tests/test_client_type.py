"""shield360.client_type: the same classifications and reasons as the TypeScript SDK."""

import os

from shield360.client_type import BreadthCounter, classify_client

CHROME = "mozilla/5.0 (macintosh) applewebkit/537.36 chrome/131.0 safari/537.36"
BROWSER = {"user-agent": CHROME, "sec-ch-ua": '"Chromium"', "sec-fetch-mode": "navigate", "accept-language": "en"}


def test_person_and_order_of_trust():
    assert classify_client(BROWSER) == {"clientType": "human", "reasons": [], "confidence": "low"}
    assert (
        classify_client({"user-agent": "python-requests/2.31"}, {"verifiedAgent": True, "trapHit": True})["clientType"]
        == "verified_agent"
    )
    assert classify_client(BROWSER, {"trapHit": True})["reasons"] == ["trap_hit"]
    assert classify_client(BROWSER, {"edge": {"ct": "verified_crawler"}})["clientType"] == "verified_agent"
    assert classify_client(BROWSER, {"edge": {"trap": 2}})["reasons"] == ["edge:trap_level_2"]


def test_signatures_and_reasons():
    assert classify_client({"user-agent": "Mozilla/5.0 (compatible; Claude-User/1.0)"})["reasons"] == ["ua_ai_agent:claude-user"]
    assert classify_client({"user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2)"})["clientType"] == "unverified_automation"
    assert classify_client({"user-agent": "curl/8.4.0"})["reasons"] == ["ua_automation:curl"]
    assert classify_client({})["reasons"] == ["no_user_agent"]
    assert classify_client({"user-agent": CHROME})["reasons"] == ["browser_headers_missing"]
    assert classify_client({"user-agent": "python-httpx/0.27"}, {"breadth": 40})["clientType"] == "suspected_ai_agent"


def test_breadth_counter():
    b = BreadthCounter(1.0, 2)
    assert [b.see("a", "/x", 0), b.see("a", "/y", 0.01), b.see("a", "/y", 0.02), b.see("a", "/z", 2)] == [1, 2, 2, 1]


def test_byte_identical_signatures():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "..", "src", "shield360", "client_type", "signatures.json"), "rb") as a, open(
        os.path.join(here, "..", "..", "client-type", "signatures.json"), "rb"
    ) as b:
        assert a.read() == b.read()
