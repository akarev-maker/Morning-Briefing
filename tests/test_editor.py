"""Tests for editor.py with a fake Gemini client. No network."""

import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import editor  # noqa: E402


def _story(sid, category, title=None):
    return {
        "id": sid,
        "category": category,
        "title": title or f"Story {sid}",
        "link": f"https://example.com/{sid}",
        "summary": f"Summary of {sid}.",
        "sources": ["Bleeping Computer"],
        "coverage": 1,
        "points": None,
        "exploited": False,
        "has_poc": False,
    }


STORIES = [_story("c1", "cyber"), _story("c2", "cyber"), _story("a1", "ai"), _story("a2", "ai")]
POOL = editor.candidates(STORIES)

GOOD = {
    "cyber": [{"id": "c2", "why": "Matters because X."}, {"id": "c1", "why": "Y."}],
    "ai": [{"id": "a1", "why": "Z."}],
    "project": {
        "title": "Train a small verifier model",
        "pitch": "Build a model that checks other models' code.",
        "milestones": ["Collect data", "Train", "Evaluate"],
        "stack": ["PyTorch", "Hugging Face"],
        "inspired_by": ["a1"],
    },
}


class FakeClient:
    """Stands in for openai.OpenAI. `answers` maps model name to a JSON string,
    or to an exception to raise."""

    answers = {}
    calls = []

    def __init__(self, **kwargs):
        FakeClient.init_kwargs = kwargs
        self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self._create))

    def _create(self, **kw):
        FakeClient.calls.append(kw["model"])
        answer = FakeClient.answers[kw["model"]]
        if isinstance(answer, Exception):
            raise answer
        choice = types.SimpleNamespace(message=types.SimpleNamespace(content=answer),
                                       finish_reason="stop" if answer else "length")
        return types.SimpleNamespace(choices=[choice])


@pytest.fixture
def gemini(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(editor, "OpenAI", FakeClient)
    FakeClient.calls = []
    return FakeClient


# --- validation -----------------------------------------------------------------
def test_valid_answer_keeps_model_order_and_feed_links():
    picks = editor.parse_picks(json.dumps(GOOD), POOL)
    assert [s["id"] for s in picks["cyber"]] == ["c2", "c1"]
    assert picks["cyber"][0]["why"] == "Matters because X."
    assert picks["cyber"][0]["link"] == "https://example.com/c2"  # from the feed, not the model
    assert picks["project"]["inspired_by"] == [{"title": "Story a1", "link": "https://example.com/a1"}]


def test_invented_and_cross_section_ids_are_dropped():
    answer = {"cyber": [{"id": "c1", "why": "ok"}, {"id": "made-up", "why": "x"},
                        {"id": "a1", "why": "AI story in the cyber list"},
                        {"id": "c1", "why": "repeat"}],
              "ai": []}
    picks = editor.parse_picks(json.dumps(answer), POOL)
    assert [s["id"] for s in picks["cyber"]] == ["c1"]
    assert picks["ai"] == []


def test_model_text_is_stripped_of_markup_and_capped():
    answer = {"cyber": [{"id": "c1", "why": "<a href='javascript:x'>click</a> " + "a" * 1000}],
              "ai": []}
    why = editor.parse_picks(json.dumps(answer), POOL)["cyber"][0]["why"]
    assert "<a" not in why and len(why) <= editor.WHY_CHARS + 1


def test_bad_project_is_dropped_but_picks_survive():
    answer = {**GOOD, "project": {"title": "", "pitch": "no title"}}
    picks = editor.parse_picks(json.dumps(answer), POOL)
    assert picks["project"] is None and picks["cyber"]

    answer = {**GOOD, "project": {**GOOD["project"], "inspired_by": ["fake-id"],
                                  "milestones": "not a list"}}
    project = editor.parse_picks(json.dumps(answer), POOL)["project"]
    assert project["inspired_by"] == [] and project["milestones"] == []


@pytest.mark.parametrize("answer", ["not json", "[1, 2]", json.dumps({"cyber": [], "ai": []}),
                                    json.dumps({"cyber": [{"id": "nope"}]})])
def test_unusable_answers_raise(answer):
    with pytest.raises(ValueError):
        editor.parse_picks(answer, POOL)


def test_prompt_lists_ids_and_facts():
    stories = [{**_story("c1", "cyber"), "coverage": 3, "exploited": True,
                "sources": ["A", "B", "C"]}]
    prompt = editor.build_prompt(editor.candidates(stories))
    assert "[c1] (A, B, C; 3 outlet(s); CVE in CISA KEV)" in prompt
    assert "(none today)" in prompt  # empty AI section


# --- calling the model ----------------------------------------------------------
def test_edit_uses_first_model_when_it_works(gemini):
    gemini.answers = {"gemini-4-hydrogen": json.dumps(GOOD)}
    picks = editor.edit(STORIES)
    assert picks["model"] == "gemini-4-hydrogen"
    assert gemini.calls == ["gemini-4-hydrogen"]  # no fallback calls
    assert gemini.init_kwargs["timeout"] == editor.TIMEOUT_SECONDS
    assert gemini.init_kwargs["max_retries"] == 0


def test_models_are_tried_in_order(gemini):
    gemini.answers = {"gemini-4-hydrogen": RuntimeError("404 model retired"),
                      "gemini-flash-latest": RuntimeError("503 high demand"),
                      "gemini-flash-lite-latest": json.dumps(GOOD)}
    assert editor.edit(STORIES)["model"] == "gemini-flash-lite-latest"
    assert gemini.calls == list(editor.MODELS)


def test_bad_answer_also_falls_back(gemini):
    gemini.answers = {"gemini-4-hydrogen": "not json", "gemini-flash-latest": json.dumps(GOOD)}
    assert editor.edit(STORIES)["model"] == "gemini-flash-latest"


def test_every_model_failing_returns_none(gemini):
    gemini.answers = {m: TimeoutError("timed out") for m in editor.MODELS}
    assert editor.edit(STORIES) is None


def test_no_key_returns_none_without_calling(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(editor, "OpenAI", lambda **kw: pytest.fail("should not be called"))
    assert editor.edit(STORIES) is None


def test_no_stories_returns_none(gemini):
    assert editor.edit([]) is None
    assert gemini.calls == []
