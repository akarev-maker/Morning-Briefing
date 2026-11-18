"""End-to-end tests of briefing.py with every outside call faked.

Each test runs in its own temp directory (monkeypatch.chdir), so the real
state/sent.json and preview files are never touched.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import briefing  # noqa: E402
import fetcher  # noqa: E402
import hackathons  # noqa: E402
import state  # noqa: E402


def _news():
    return [
        fetcher._story("Bleeping Computer", "cyber", "Optimizely hack hits CNN",
                       "https://bleepingcomputer.com/optimizely", "Skimmer on news sites.", None),
        fetcher._story("OpenAI", "ai", "Introducing GPT-6.2",
                       "https://openai.com/gpt-6-2", "A new model.", None),
    ]


def _papers():
    paper = fetcher._paper({"paper": {"id": "2611.00001", "title": "Continual learning without forgetting",
                                      "summary": "A new method.", "upvotes": 40,
                                      "submittedOnDailyAt": "2026-11-18T00:00:00.000Z"}})
    return [paper]


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """Fake sources and SMTP. Returns the list that collects sent emails."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)  # coverage ranking unless a test opts in
    monkeypatch.setattr(fetcher, "fetch_all",
                        lambda: {"news": _news(), "papers": _papers(), "kev": {}, "ctf": [],
                                 "generated_at": ""})
    monkeypatch.setattr(hackathons, "fetch_hackathons", lambda: [])
    outbox = []
    monkeypatch.setattr(briefing, "send_email",
                        lambda subject, html, text: outbox.append((subject, html, text)))
    return outbox


def test_dry_run_writes_preview_and_records_nothing(pipeline, tmp_path):
    briefing.main(["--dry-run"])
    assert pipeline == []  # nothing sent
    assert "Optimizely hack hits CNN" in (tmp_path / "preview.html").read_text()
    assert "GPT-6.2" in (tmp_path / "preview.txt").read_text()
    assert not (tmp_path / "state" / "sent.json").exists()


def test_real_run_sends_then_records(pipeline, tmp_path):
    briefing.main([])
    assert len(pipeline) == 1
    subject, html, _ = pipeline[0]
    assert subject.startswith("Morning Briefing")
    assert "Optimizely hack hits CNN" in html
    sent = state.load_sent(str(tmp_path / "state" / "sent.json"))
    assert f"story:{fetcher.story_id('https://openai.com/gpt-6-2')}" in sent


def test_second_run_does_not_repeat_stories(pipeline):
    briefing.main([])
    briefing.main([])
    _, second_html, _ = pipeline[1]
    assert "Optimizely hack hits CNN" not in second_html
    assert "No new security stories today." in second_html


def test_failed_send_records_nothing(pipeline, tmp_path, monkeypatch):
    def smtp_down(*args):
        raise ConnectionError("SMTP down")

    monkeypatch.setattr(briefing, "send_email", smtp_down)
    with pytest.raises(ConnectionError):
        briefing.main([])
    assert not (tmp_path / "state" / "sent.json").exists()


def test_only_shown_stories_are_recorded(pipeline, tmp_path, monkeypatch):
    # Distinct headlines (similar ones would correctly cluster into one story).
    titles = ["Uber driver data breach", "Tor fights DDoS", "Fugaku supercomputer offline",
              "Docker Hub keys stolen", "Telegram widget bypass", "Phrack 73 released",
              "ScreenConnect attacks continue", "iPhone microphone flaw",
              "Ransomware suspect extradited", "Project Zero shortens deadline"]
    many = [fetcher._story("Dark Reading", "cyber", t, f"https://darkreading.com/{i}", "", None)
            for i, t in enumerate(titles)]
    monkeypatch.setattr(fetcher, "fetch_all",
                        lambda: {"news": many, "papers": [], "kev": {}, "ctf": [],
                                 "generated_at": ""})
    briefing.main([])
    sent = state.load_sent(str(tmp_path / "state" / "sent.json"))
    assert len([k for k in sent if k.startswith("story:")]) == briefing.STORIES_PER_SECTION["cyber"]


def test_papers_get_their_own_section_and_are_recorded(pipeline, tmp_path):
    briefing.main([])
    _, html, _ = pipeline[0]
    assert "Research papers" in html
    assert "Continual learning without forgetting" in html and "40 upvotes" in html
    assert "https://arxiv.org/abs/2611.00001" in html
    sent = state.load_sent(str(tmp_path / "state" / "sent.json"))
    assert f"story:{fetcher.story_id('https://arxiv.org/abs/2611.00001')}" in sent

    briefing.main([])  # the same paper doesn't come back tomorrow
    assert "Continual learning without forgetting" not in pipeline[1][1]


def test_gemini_picks_and_project_reach_the_email(pipeline, monkeypatch):
    stories_seen = []

    def fake_edit(stories):
        stories_seen.extend(stories)
        ai = next(s for s in stories if s["category"] == "ai")
        return {"cyber": [], "ai": [{**ai, "why": "A frontier model release."}],
                "project": {"title": "Build an eval harness", "pitch": "Long pitch.",
                            "milestones": [], "stack": [], "inspired_by": []},
                "model": "gemini-flash-latest"}

    monkeypatch.setattr(briefing.editor, "edit", fake_edit)
    briefing.main([])
    _, html, _ = pipeline[0]
    assert "A frontier model release." in html and "Build an eval harness" in html
    assert "Optimizely hack hits CNN" not in html  # Gemini didn't pick it
    assert "Stories picked by gemini-flash-latest." in html
    assert len(stories_seen) == 3  # the editor saw every candidate: 2 news + 1 paper


def test_failure_email_no_crash_without_env(monkeypatch):
    for var in ("EMAIL_SENDER", "EMAIL_RECIPIENT", "EMAIL_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    briefing.send_failure_email("boom")  # should log and return, not raise
