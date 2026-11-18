"""Tests for render.py: every section draws, and nothing hostile gets through."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import render  # noqa: E402

TODAY = date(2026, 11, 18)


def _story(title="Java4Shell RCE", link="https://bleepingcomputer.com/java4shell", **kw):
    story = {
        "id": "abc",
        "category": "cyber",
        "title": title,
        "link": link,
        "summary": "A critical flaw in OpenJDK lets attackers run code.",
        "sources": ["Bleeping Computer", "Hacker News"],
        "coverage": 2,
        "points": 505,
        "comments": "https://news.ycombinator.com/item?id=1",
        "cve_info": [],
        "exploited": False,
        "has_poc": False,
    }
    story.update(kw)
    return story


def _hackathon(name="BostonHacks", **kw):
    h = {
        "name": name,
        "url": "https://bostonhacks.org/",
        "start": date(2026, 11, 21),
        "end": date(2026, 11, 22),
        "location": "Boston, MA",
        "online": False,
        "registrations": None,
        "prize": "",
        "source": "MLH",
        "school": "Boston University",
        "starting_soon": True,
    }
    h.update(kw)
    return h


def _briefing(**kw):
    b = {
        "cyber": [_story()],
        "ai": [_story("GPT-6.2 Astra and Sol", "https://openai.com/gpt-6-2", category="ai")],
        "project": None,
        "edited": False,
        "hackathons": {"nearby": [_hackathon()], "online": []},
        "ctf": [{"title": "Splice CTF", "start": "2026-11-22T00:00:00+00:00",
                 "url": "https://ctftime.org/event/1", "onsite": False, "format": "Jeopardy"}],
        "status": {"Krebs on Security": {"state": "ok", "count": 0, "error": ""}},
        "degraded": False,
    }
    b.update(kw)
    return b


def test_every_section_renders():
    _, html, text = render.render(_briefing(), TODAY)
    for heading in ("Cybersecurity", "AI and machine learning", "Hackathons", "CTFs"):
        assert heading in html
        assert heading.upper() in text
    assert "Java4Shell RCE" in html and "Splice CTF" in html and "BostonHacks" in html
    assert "2 outlets" in html and "505 points on HN" in html
    assert "Worth applying: Boston University" in html
    assert "Nov 21–22 (in 3 days)" in html


def test_empty_sections_show_one_quiet_line():
    _, html, text = render.render(
        _briefing(cyber=[], ai=[], hackathons={"nearby": [], "online": []}, ctf=[]), TODAY)
    for line in ("No new security stories today.", "No new AI stories today.",
                 "No new hackathons today.", "No CTFs found for the next three weeks."):
        assert line in html and line in text


def test_plain_text_contains_every_link():
    b = _briefing()
    b["cyber"][0]["cve_info"] = [{"id": "CVE-2026-114938", "kev": False,
                                  "pocs": [{"url": "https://github.com/x/poc"}]}]
    _, html, text = render.render(b, TODAY)
    for url in ("https://bleepingcomputer.com/java4shell", "https://openai.com/gpt-6-2",
                "https://bostonhacks.org/", "https://ctftime.org/event/1",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-114938", "https://github.com/x/poc"):
        assert url in text, url
        assert url in html, url


def test_cve_tags():
    story = _story(exploited=True, has_poc=True,
                   cve_info=[{"id": "CVE-2026-1", "kev": True, "ransomware": True,
                              "pocs": [{"url": "https://github.com/x/poc"}]}])
    html = render.render_html(_briefing(cyber=[story]), TODAY)
    assert "Exploited in the wild (CISA KEV)" in html
    assert "Used in ransomware" in html
    assert "Public exploit code" in html


def test_hostile_text_is_escaped():
    evil = _story(title='<img src=x onerror=alert(1)> "quoted"',
                  summary="<script>alert(1)</script>")
    html = render.render_html(_briefing(cyber=[evil]), TODAY)
    assert "<img" not in html and "<script" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_hostile_links_are_dropped_but_text_stays():
    for bad in ("javascript:alert(1)", "java\tscript:alert(1)", "data:text/html,x"):
        html = render.render_html(_briefing(cyber=[_story(title="Click me", link=bad)]), TODAY)
        assert "javascript" not in html.lower() and "data:text" not in html, bad
        assert "Click me" in html


def test_link_with_quote_cannot_break_out_of_href():
    html = render.render_html(
        _briefing(cyber=[_story(link='https://x.example/"onmouseover="alert(1)')]), TODAY)
    assert '"onmouseover="' not in html
    assert "&quot;onmouseover=&quot;" in html


def test_footer_reports_source_problems():
    status = {
        "Bleeping Computer": {"state": "ok", "count": 15, "error": ""},
        "MLH": {"state": "empty", "count": 0, "error": ""},
        "Devpost": {"state": "partial", "count": 54, "error": "timeout"},
        "CTFtime": {"state": "failed", "count": 0, "error": "503"},
    }
    _, html, text = render.render(_briefing(status=status), TODAY)
    assert "1 of 4 sources OK" in html and "1 of 4 sources OK" in text
    assert "MLH: returned nothing (possible failure)" in html
    assert "Devpost: partly failed (54 items)" in html
    assert "CTFtime: failed" in text


def test_footer_all_ok_and_ranking_note():
    html = render.render_html(_briefing(), TODAY)
    assert "All 1 sources OK" in html
    assert "ranked by how many outlets covered them" in html
    edited = render.render_html(_briefing(edited=True, model="gemini-flash-latest"), TODAY)
    assert "Stories picked by gemini-flash-latest." in edited


def test_degraded_banner():
    assert "No news was fetched today" in render.render_html(_briefing(degraded=True), TODAY)
    assert "No news was fetched today" not in render.render_html(_briefing(), TODAY)


def test_online_hackathon_already_open():
    h = _hackathon("Kiroween", online=True, location="Online", start=date(2026, 10, 30),
                   end=date(2026, 12, 4), registrations=15975, prize="$100,000",
                   school=None, starting_soon=False, source="Devpost")
    html = render.render_html(_briefing(hackathons={"nearby": [], "online": [h]}), TODAY)
    assert "Open now, ends Dec 4" in html
    assert "15,975 registered" in html and "$100,000 in prizes" in html


def test_project_box_renders_when_present():
    project = {"title": "Build a verifier", "pitch": "Long pitch.", "milestones": ["One", "Two"],
               "stack": ["PyTorch"], "inspired_by": [{"title": "GPT-6.2", "link": "https://o.ai"}]}
    _, html, text = render.render(_briefing(project=project), TODAY)
    assert "Project idea" in html and "Build a verifier" in html and "PyTorch" in text
    assert "Project idea" not in render.render_html(_briefing(), TODAY)


def test_subject():
    assert render.subject(TODAY) == "Morning Briefing · Wed Nov 18"
