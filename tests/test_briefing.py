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
    fetcher.flag_new_jobs(jobs, seen={"a"})
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


# --- briefing: skill-builder keyword matching -----------------------------
def test_skillbuilder_matches_todays_vulns():
    data = {
        "cves": [{"description": "A SQL injection in the login form"}],
        "kev": [],
        "news": [{"title": "New SSRF technique disclosed"}],
    }
    md = briefing.build_skillbuilder_markdown(data)
    assert "SQL injection" in md
    assert "SSRF" in md
    assert "Burp Suite" in md  # pinned resource always present


def test_poc_note():
    assert briefing._poc_note([]) == ""
    assert "public PoC" in briefing._poc_note([{"url": "http://x", "stars": 3}])


# --- briefing: HTB section only when data present -------------------------
def test_htb_section_empty_without_data():
    assert briefing.build_htb_markdown(None) == ""


def test_htb_section_rendered_with_data():
    md = briefing.build_htb_markdown({"name": "hacker", "rank": "Pro Hacker", "points": 42})
    assert "Pro Hacker" in md
    assert "hacker" in md
