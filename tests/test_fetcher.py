"""Tests for fetcher.py. No network: every outside call is replaced with a fake."""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fetcher  # noqa: E402


class FakeResponse:
    def __init__(self, payload=None, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


# --- one broken source never kills the run ---------------------------------
def test_fetch_all_returns_only_v2_sections(monkeypatch):
    monkeypatch.setattr(fetcher, "fetch_rss_feeds", lambda: [{"category": "cyber"}])
    monkeypatch.setattr(fetcher, "fetch_hn", lambda: [{"category": "ai"}])
    monkeypatch.setattr(fetcher, "fetch_papers", lambda: [])
    monkeypatch.setattr(fetcher, "fetch_kev", lambda: {"CVE-2026-1": {}})
    monkeypatch.setattr(fetcher, "fetch_ctf_events", lambda: [])
    data = fetcher.fetch_all()
    assert set(data) == {"news", "papers", "kev", "ctf", "generated_at"}


def test_fetch_all_survives_every_source_failing(monkeypatch):
    def boom(*args, **kwargs):
        raise ConnectionError("network down")

    monkeypatch.setattr(fetcher.SESSION, "get", boom)
    fetcher.reset_status()
    data = fetcher.fetch_all()  # must not raise
    assert data["news"] == [] and data["kev"] == {} and data["ctf"] == []
    assert data["papers"] == []
    # ...and every source is reported as failed, for the email footer.
    assert fetcher.source_status
    assert all(s["state"] == "failed" for s in fetcher.source_status.values())


# --- source status ---------------------------------------------------------
def test_record_source_states():
    fetcher.reset_status()
    fetcher.record_source("A", 5)
    fetcher.record_source("B", 0)  # quiet blog: zero is fine
    fetcher.record_source("C", 0, expect_items=True)  # should never be zero
    fetcher.record_source("D", 0, error=TimeoutError("slow"))
    fetcher.record_source("E", 54, error=TimeoutError("page 7"))
    states = {k: v["state"] for k, v in fetcher.source_status.items()}
    assert states == {"A": "ok", "B": "ok", "C": "empty", "D": "failed", "E": "partial"}
    assert fetcher.source_status["D"]["error"] == "slow"


def test_kev_renamed_field_is_flagged_not_silent(monkeypatch):
    # CISA renames "vulnerabilities": no exception, but zero entries.
    monkeypatch.setattr(fetcher.SESSION, "get", lambda *a, **k: FakeResponse({"vulns": []}))
    fetcher.reset_status()
    assert fetcher.fetch_kev() == {}
    assert fetcher.source_status["CISA KEV"]["state"] == "empty"


# --- categories and Hacker News --------------------------------------------
def test_classify_title():
    assert fetcher.classify_title("Java4Shell: RCE in OpenJDK when processing Base64") == "cyber"
    assert fetcher.classify_title("GPT-6.2 Astra and Sol") == "ai"
    assert fetcher.classify_title("How the Claude Code team thinks about verification") == "ai"
    assert fetcher.classify_title("jQuery 4.1.0") is None
    # Whole words only: "ai" inside "said"/"again" must not count.
    assert fetcher.classify_title("Comcast said again that fiber is cable") is None
    # Both match: security wins.
    assert fetcher.classify_title("AI agents used to spread malware") == "cyber"


def _hn_entry(title, points="386"):
    return {
        "title": title,
        "link": "https://calif.io/java4shell/",
        "comments": "https://news.ycombinator.com/item?id=50538240",
        "summary": f"<p>Article URL: ...</p>\n<p>Points: {points}</p>\n<p># Comments: 95</p>",
        "published_parsed": None,
    }


def test_hn_story_parses_points_and_category():
    story = fetcher._hn_story(_hn_entry("Java4Shell: RCE in OpenJDK"))
    assert story["category"] == "cyber"
    assert story["points"] == 386
    assert story["comments"] == "https://news.ycombinator.com/item?id=50538240"
    assert story["summary"] == ""  # hnrss boilerplate is not a summary


def test_hn_story_skips_off_topic():
    assert fetcher._hn_story(_hn_entry("Solid 2.0")) is None


def test_story_id_ignores_tracking_and_trailing_slash():
    a = fetcher.story_id("https://www.example.com/post/?utm_source=rss")
    b = fetcher.story_id("http://example.com/post")
    assert a == b
    assert a != fetcher.story_id("https://example.com/other")


# --- Hugging Face papers ---------------------------------------------------
def _hf(arxiv_id="2611.17621", upvotes=40, submitted=None, repo=None):
    from datetime import datetime, timezone
    submitted = submitted or datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00.000Z")
    return {"paper": {"id": arxiv_id, "title": "Continual <b>learning</b>",
                      "summary": "New idea.", "upvotes": upvotes,
                      "submittedOnDailyAt": submitted, "githubRepo": repo}}


def test_paper_fields():
    p = fetcher._paper(_hf(repo="https://github.com/x/y"))
    assert p["category"] == "papers" and p["title"] == "Continual learning"
    assert p["link"] == "https://arxiv.org/abs/2611.17621"
    assert p["comments"] == "https://huggingface.co/papers/2611.17621"
    assert p["upvotes"] == 40 and p["code"] == "https://github.com/x/y"


def test_paper_with_bad_id_or_link_is_rejected():
    assert fetcher._paper(_hf(arxiv_id="../../evil")) is None
    assert fetcher._paper(_hf(repo="javascript:alert(1)"))["code"] == ""


def test_fetch_papers_filters_votes_and_age(monkeypatch):
    items = [_hf("2611.00001", upvotes=90), _hf("2611.00002", upvotes=3),
             _hf("2611.00003", upvotes=50, submitted="2026-01-01T00:00:00.000Z"),
             _hf("2611.00004", upvotes=20)]
    monkeypatch.setattr(fetcher.SESSION, "get", lambda *a, **k: FakeResponse(items))
    papers = fetcher.fetch_papers()
    assert [p["upvotes"] for p in papers] == [90, 20]  # too few votes and too old dropped


# --- KEV and PoC -----------------------------------------------------------
def test_fetch_kev_builds_lookup_by_cve_id(monkeypatch):
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1234",
                "vulnerabilityName": "PHP <b>RCE</b>",
                "dateAdded": "2026-11-01",
                "knownRansomwareCampaignUse": "Known",
            }
        ]
    }
    monkeypatch.setattr(fetcher.SESSION, "get", lambda *a, **k: FakeResponse(payload))
    kev = fetcher.fetch_kev()
    assert kev["CVE-2026-1234"]["name"] == "PHP RCE"  # tags stripped
    assert kev["CVE-2026-1234"]["ransomware"] == "Known"


def test_pocs_for_cve_404_means_none():
    session = types.SimpleNamespace(get=lambda *a, **k: FakeResponse(status=404))
    assert fetcher.pocs_for_cve("CVE-2026-1234", session) == []


def test_pocs_for_cve_sorted_and_scheme_checked():
    repos = [
        {"html_url": "https://github.com/a/low", "stargazers_count": 1},
        {"html_url": "javascript:alert(1)", "stargazers_count": 99},
        {"html_url": "https://github.com/b/high", "stargazers_count": 50},
    ]
    session = types.SimpleNamespace(get=lambda *a, **k: FakeResponse(repos))
    pocs = fetcher.pocs_for_cve("CVE-2026-1234", session)
    assert [p["url"] for p in pocs] == ["https://github.com/b/high", "https://github.com/a/low"]


# --- untrusted input is cleaned at the point of entry -----------------------
def test_strip_html_removes_tags():
    assert "<img" not in fetcher._strip_html("Acme <img src=x onerror=alert(1)> Co")
    assert "script" not in fetcher._strip_html("<script>alert(1)</script>").lower()


def test_strip_html_decodes_entities():
    assert fetcher._strip_html("Go Proverbs &mdash; via") == "Go Proverbs — via"
    # An escaped tag decodes to plain text. It is not markup any more, and
    # render.py escapes it again before it reaches HTML.
    assert fetcher._strip_html("&lt;b&gt;hi") == "<b>hi"


def test_safe_url_blocks_non_http():
    assert fetcher.safe_url("javascript:alert(1)") == ""
    assert fetcher.safe_url("data:text/html,x") == ""
    assert fetcher.safe_url("https://ok.com") == "https://ok.com"


def test_safe_url_ignores_whitespace_obfuscation():
    # Browsers ignore whitespace and control chars inside a scheme, so
    # "java\tscript:" is a working link and must be caught.
    assert fetcher.safe_url("java\tscript:alert(1)") == ""
    assert fetcher.safe_url("  javascript:alert(1)") == ""
    assert fetcher.safe_url("JAVASCRIPT:alert(1)") == ""
    assert fetcher.safe_url(None) == ""
    assert fetcher.safe_url("https://ok.com/a?b=1&c=2") == "https://ok.com/a?b=1&c=2"


def test_feed_links_are_scheme_checked_at_ingest(monkeypatch):
    """A hostile feed's javascript: link must never enter the pipeline."""
    entry = {
        "title": "Breaking news",
        "link": "javascript:alert(document.cookie)",
        "summary": "click me",
        "published_parsed": None,
    }
    feed = types.SimpleNamespace(bozo=False, entries=[entry], bozo_exception=None)
    monkeypatch.setattr(fetcher, "CYBER_FEEDS", {"Evil Feed": "https://evil.example/rss"})
    monkeypatch.setattr(fetcher, "AI_FEEDS", {})
    monkeypatch.setattr(fetcher, "_parse_feed", lambda url, timeout=30: feed)

    items = fetcher.fetch_rss_feeds()
    assert len(items) == 1
    assert items[0]["link"] == ""


def test_ctf_url_falls_back_when_primary_is_unsafe():
    events = [{"title": "CTF", "start": "2026-08-10T13:00:00+00:00",
               "url": "javascript:alert(1)", "ctftime_url": "https://ctftime.org/event/1"}]
    parsed = fetcher._parse_ctf_events(events)
    assert parsed[0]["url"] == "https://ctftime.org/event/1"
