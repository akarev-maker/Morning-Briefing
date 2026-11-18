"""Unit tests. No network: every outside call is replaced with a fake.

Run with: pytest
"""

import sys
import types
from pathlib import Path

# Make the top-level modules importable when pytest runs from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import briefing  # noqa: E402
import fetcher  # noqa: E402


def _data(**overrides):
    data = {"news": [], "kev": {}, "ctf": []}
    data.update(overrides)
    return data


class _FakeResponse:
    def __init__(self, payload=None, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


# --- fetcher: one broken source never kills the run ------------------------
def test_fetch_all_returns_only_v2_sections(monkeypatch):
    monkeypatch.setattr(fetcher, "fetch_rss_feeds", lambda: [{"category": "cyber"}])
    monkeypatch.setattr(fetcher, "fetch_hn", lambda: [{"category": "ai"}])
    monkeypatch.setattr(fetcher, "fetch_kev", lambda: {"CVE-2026-1": {}})
    monkeypatch.setattr(fetcher, "fetch_ctf_events", lambda: [])
    data = fetcher.fetch_all()
    assert set(data) == {"news", "kev", "ctf", "generated_at"}


def test_fetch_all_survives_every_source_failing(monkeypatch):
    def boom(*args, **kwargs):
        raise ConnectionError("network down")

    monkeypatch.setattr(fetcher.SESSION, "get", boom)
    data = fetcher.fetch_all()  # must not raise
    assert data["news"] == [] and data["kev"] == {} and data["ctf"] == []


# --- fetcher: categories and Hacker News -----------------------------------
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
    monkeypatch.setattr(fetcher.SESSION, "get", lambda *a, **k: _FakeResponse(payload))
    kev = fetcher.fetch_kev()
    assert kev["CVE-2026-1234"]["name"] == "PHP RCE"  # tags stripped
    assert kev["CVE-2026-1234"]["ransomware"] == "Known"


def test_pocs_for_cve_404_means_none():
    session = types.SimpleNamespace(get=lambda *a, **k: _FakeResponse(status=404))
    assert fetcher.pocs_for_cve("CVE-2026-1234", session) == []


def test_pocs_for_cve_sorted_and_scheme_checked():
    repos = [
        {"html_url": "https://github.com/a/low", "stargazers_count": 1},
        {"html_url": "javascript:alert(1)", "stargazers_count": 99},
        {"html_url": "https://github.com/b/high", "stargazers_count": 50},
    ]
    session = types.SimpleNamespace(get=lambda *a, **k: _FakeResponse(repos))
    pocs = fetcher.pocs_for_cve("CVE-2026-1234", session)
    assert [p["url"] for p in pocs] == ["https://github.com/b/high", "https://github.com/a/low"]


# --- briefing: code-built CTF section --------------------------------------
def test_assemble_inserts_ctfs_before_quick_hits():
    ctf = [{"title": "Splice CTF", "start": "2026-12-01T00:00:00+00:00", "url": "https://x"}]
    ai = "## Top Stories\n- x\n\n## Quick Hits\n- y"
    out = briefing.assemble_briefing(ai, _data(ctf=ctf))
    assert out.index(briefing.CTF_HEADING) < out.index(briefing.QUICK_HITS_HEADING)
    assert "Splice CTF" in out


def test_assemble_strips_model_written_ctf_section():
    ai = (
        "## Top Stories\n- x\n\n"
        "## Upcoming CTFs\n- Model's made-up CTF\n\n"
        "## Quick Hits\n- y"
    )
    out = briefing.assemble_briefing(ai, _data())
    assert "Model's made-up CTF" not in out
    assert out.count(briefing.CTF_HEADING) == 1


def test_fallback_lists_news_and_ctfs():
    news = [{"title": "Big Story", "link": "https://a", "source": "Krebs", "summary": ""}]
    out = briefing.fallback_markdown(_data(news=news))
    assert "Big Story" in out and briefing.CTF_HEADING in out


def test_degraded_banner_only_when_no_news():
    assert briefing.degraded_banner(_data()) != ""
    assert briefing.degraded_banner(_data(news=[{"title": "x"}])) == ""


# --- security: untrusted input can't inject markup or links ----------------
def test_strip_html_removes_tags():
    assert "<img" not in fetcher._strip_html("Acme <img src=x onerror=alert(1)> Co")
    assert "script" not in fetcher._strip_html("<script>alert(1)</script>").lower()


def test_md_escapes_control_chars():
    out = briefing._md("Evil [click](http://bad) **x**")
    assert "\\[" in out and "\\]" in out and "\\*" in out


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
    assert "javascript" not in briefing._format_data_for_prompt(_data(news=items))


def test_ctf_url_falls_back_when_primary_is_unsafe():
    events = [{"title": "CTF", "start": "2026-08-10T13:00:00+00:00",
               "url": "javascript:alert(1)", "ctftime_url": "https://ctftime.org/event/1"}]
    parsed = fetcher._parse_ctf_events(events)
    assert parsed[0]["url"] == "https://ctftime.org/event/1"


def test_hostile_ctf_title_cannot_forge_link_or_markup():
    import markdown as mdlib

    evil = [{"title": "Nice <img src=x> [phish](http://evil)", "start": "",
             "url": "https://real"}]
    html = mdlib.markdown(briefing.build_ctf_markdown(evil), extensions=["extra"])
    assert "<img" not in html
    assert 'href="http://evil"' not in html
    assert 'href="https://real"' in html


def test_render_html_neutralizes_model_written_dangerous_links():
    """The model writes its own links, so the rendered HTML is checked too."""
    for bad in (
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "java\tscript:alert(1)",
        "&#106;avascript:alert(1)",
        "data:text/html,x",
    ):
        out = briefing.render_html(f"[click]({bad})", _data(), "today")
        assert "javascript" not in out.lower(), bad
        assert "data:text/html" not in out, bad
        assert 'href="#"' in out, bad


def test_render_html_preserves_legitimate_links():
    out = briefing.render_html("[ok](https://nvd.nist.gov/a?b=1&c=2)", _data(), "today")
    assert 'href="https://nvd.nist.gov/a?b=1&amp;c=2"' in out


# --- briefing: model failures surface clearly ------------------------------
def test_summarize_raises_clear_error_on_empty_response(monkeypatch):
    """An empty Gemini message must raise a readable error, not AttributeError."""

    class _Choice:
        message = types.SimpleNamespace(content=None)
        finish_reason = "length"

    class _Client:
        def __init__(self, **kwargs):
            self.chat = types.SimpleNamespace(
                completions=types.SimpleNamespace(
                    create=lambda **kw: types.SimpleNamespace(choices=[_Choice()])
                )
            )

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(briefing, "OpenAI", _Client)

    try:
        briefing.summarize(_data())
    except RuntimeError as exc:
        assert "finish_reason" in str(exc) and "length" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for an empty model response")


def test_failure_email_no_crash_without_env(monkeypatch):
    for var in ("EMAIL_SENDER", "EMAIL_RECIPIENT", "EMAIL_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    briefing.send_failure_email("boom")  # should log and return, not raise
