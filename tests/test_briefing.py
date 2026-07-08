"""Network-free unit tests for the briefing's deterministic logic.

These cover the parts that must never silently break — new-job flagging, the
"never drop an internship" guarantee, section assembly, and relevance filters.
Run with: pytest
"""

import sys
from pathlib import Path

# Make the top-level modules importable when pytest runs from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import briefing  # noqa: E402
import fetcher  # noqa: E402


def _job(title, link, rank=2, is_new=False, company="Acme", term="Summer 2026"):
    # Wrap bare identifiers into real URLs (the code correctly drops non-http links).
    if not link.startswith("http"):
        link = f"https://example.com/{link}"
    return {
        "title": title,
        "link": link,
        "company": company,
        "locations": ["Boston, MA"] if rank == 0 else ["Remote"],
        "location_str": "Boston, MA" if rank == 0 else "Remote",
        "term": term,
        "category": "Security",
        "sponsorship": "",
        "degrees": [],
        "date_posted": 0,
        "rank": rank,
        "is_new": is_new,
    }


# --- fetcher: relevance + ranking -----------------------------------------
def test_is_security_role():
    assert fetcher._is_security_role("Penetration Testing Intern")
    assert fetcher._is_security_role("Cybersecurity Analyst Intern")
    assert not fetcher._is_security_role("Frontend Developer Intern")


def test_location_rank_ma_first():
    assert fetcher._location_rank(["Boston, MA"]) == 0
    assert fetcher._location_rank(["Cambridge, Massachusetts"]) == 0
    assert fetcher._location_rank(["Remote"]) == 1
    assert fetcher._location_rank(["San Jose, CA"]) == 2


def test_location_rank_ma_not_substring():
    # "ma" must not match inside another token (e.g. Norman, OK).
    assert fetcher._location_rank(["Norman, OK"]) == 2


# --- fetcher: new-job flagging --------------------------------------------
def test_flag_new_jobs_first_run_is_baseline():
    jobs = [_job("A", "a"), _job("B", "b")]
    fetcher.flag_new_jobs(jobs, seen=set())
    assert all(not j["is_new"] for j in jobs)  # nothing "new" on the first ever run


def test_flag_new_jobs_detects_new():
    jobs = [_job("A", "a"), _job("B", "b")]
    fetcher.flag_new_jobs(jobs, seen={fetcher._job_id(jobs[0])})
    assert not jobs[0]["is_new"]  # already seen
    assert jobs[1]["is_new"]  # new since last run


def test_merge_jobs_dedups_and_sorts():
    dup = _job("Dup", "same")
    ma = _job("MA role", "ma", rank=0)
    merged = fetcher._merge_jobs([dup, ma], [dict(dup)])  # dup appears twice
    assert len(merged) == 2  # deduped
    assert merged[0]["rank"] == 0  # MA sorted first


# --- briefing: never drop an internship -----------------------------------
def test_build_internships_includes_every_posting():
    jobs = [_job(f"Role {i}", f"link{i}") for i in range(15)]
    md = briefing.build_internships_markdown(jobs)
    for j in jobs:
        assert j["title"] in md
        assert j["link"] in md


def test_new_jobs_get_flag_and_counter():
    jobs = [_job("Old", "o"), _job("Fresh", "f", is_new=True)]
    md = briefing.build_internships_markdown(jobs)
    assert "🆕" in md
    assert "1 new since yesterday" in md


def test_empty_internships_has_friendly_message():
    md = briefing.build_internships_markdown([])
    assert "No active security internships" in md


# --- briefing: assembly splices code sections, strips model dupes ----------
def test_assemble_inserts_before_quick_hits_and_keeps_all_jobs():
    data = {
        "jobs": [_job("Splice Me", "splice")],
        "news": [],
        "cves": [],
        "kev": [],
        "ctf": [],
        "htb": None,
    }
    ai = "## 🔥 TOP STORIES\n- x\n\n## 📌 QUICK HITS\n- y"
    out = briefing.assemble_briefing(ai, data)
    assert out.index("💼") < out.index("📌 QUICK HITS")  # internships before quick hits
    assert "Splice Me" in out


def test_assemble_strips_model_written_internship_section():
    data = {"jobs": [_job("Real", "real")], "news": [], "cves": [], "kev": [],
            "ctf": [], "htb": None}
    # Model disobeyed and wrote its own (incomplete) internship section.
    ai = (
        "## 🔥 TOP STORIES\n- x\n\n"
        "## 💼 INTERNSHIP OPPORTUNITIES\n- Model's bad list\n\n"
        "## 📌 QUICK HITS\n- y"
    )
    out = briefing.assemble_briefing(ai, data)
    assert "Model's bad list" not in out  # stray section removed
    assert "Real" in out  # code-built list present
    assert out.count(briefing.INTERNSHIP_HEADING) == 1  # exactly one, no dupes


def test_htb_token_unwrapping():
    import base64
    import json as _json

    jwt = "eyJhbGciOi.eyJzdWIiOiJ.sig"
    assert fetcher._normalize_htb_token(jwt) == jwt  # clean passes through
    assert fetcher._normalize_htb_token("Bearer " + jwt) == jwt  # strip prefix
    assert fetcher._normalize_htb_token(_json.dumps({"token": jwt})) == jwt  # json blob
    # base64-encoded JSON blob (the localStorage 'identity' case that 401'd)
    blob = base64.b64encode(_json.dumps({"token": jwt}).encode()).decode()
    assert fetcher._normalize_htb_token(blob) == jwt


def test_poc_note():
    assert briefing._poc_note([]) == ""
    assert "public PoC" in briefing._poc_note([{"url": "http://x", "stars": 3}])


# --- security: injection neutralized ---------------------------------------
def test_strip_html_removes_tags():
    assert "<img" not in fetcher._strip_html("Acme <img src=x onerror=alert(1)> Co")
    assert "script" not in fetcher._strip_html("<script>alert(1)</script>").lower()


def test_md_escapes_control_chars():
    out = briefing._md("Evil [click](http://bad) **x**")
    assert "\\[" in out and "\\]" in out and "\\*" in out


def test_safe_url_blocks_non_http():
    assert briefing._safe_url("javascript:alert(1)") == ""
    assert briefing._safe_url("data:text/html,x") == ""
    assert briefing._safe_url("https://ok.com") == "https://ok.com"


def test_hostile_job_cannot_forge_link_or_markup():
    import markdown as mdlib

    evil = _job("Nice <img src=x onerror=alert(1)> [phish](http://evil)", "https://real")
    html = mdlib.markdown(briefing.build_internships_markdown([evil]), extensions=["extra"])
    assert "<img" not in html  # no live tag — angle brackets escaped by _md
    assert 'href="http://evil"' not in html  # forged link neutralized by _md
    assert 'href="https://real"' in html  # the legitimate link still works


# --- briefing: HTB section only when data present -------------------------
def test_htb_section_empty_without_data():
    assert briefing.build_htb_markdown(None) == ""


def test_failure_email_no_crash_without_env(monkeypatch):
    # Must degrade gracefully (log + return), never raise, when creds are absent.
    for var in ("EMAIL_SENDER", "EMAIL_RECIPIENT", "EMAIL_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    briefing.send_failure_email("boom")  # should not raise


def test_htb_academy_section_rendered():
    md = briefing.build_htb_markdown(
        {
            "name": "andyExel",
            "rank": "Hacker",
            "cubes": 120,
            "modules_completed": 8,
            "paths": [{"name": "Penetration Tester", "progress": 42}],
        }
    )
    assert "andyExel" in md
    assert "8" in md and "modules completed" in md
    assert "Penetration Tester" in md and "42%" in md
