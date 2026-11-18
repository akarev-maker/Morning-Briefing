"""Tests for the sent log (state/sent.json). Files go in pytest's tmp_path."""

import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fetcher  # noqa: E402
import state  # noqa: E402

TODAY = date(2026, 11, 18)


def _story(link, cves=(), kev=()):
    return {
        "id": fetcher.story_id(link),
        "link": link,
        "links": [link],
        "cve_info": [{"id": c, "kev": c in kev} for c in cves],
    }


def test_missing_file_means_nothing_sent(tmp_path):
    assert state.load_sent(str(tmp_path / "nope.json")) == {}


def test_corrupt_file_means_nothing_sent(tmp_path):
    p = tmp_path / "sent.json"
    p.write_text("{not json")
    assert state.load_sent(str(p)) == {}
    p.write_text("[1, 2, 3]")  # valid JSON, wrong shape
    assert state.load_sent(str(p)) == {}


def test_save_then_load_round_trip(tmp_path):
    p = str(tmp_path / "state" / "sent.json")  # directory doesn't exist yet
    state.save_sent({"story:abc": "2026-11-17"}, path=p, today=TODAY)
    assert state.load_sent(p) == {"story:abc": "2026-11-17"}


def test_prune_drops_old_and_malformed_entries():
    sent = {
        "old": "2026-11-03",      # 15 days before TODAY
        "edge": "2026-11-04",     # exactly 14 days: kept
        "recent": "2026-11-17",
        "garbage": "yesterday",
    }
    assert state.prune(sent, today=TODAY) == {"edge": "2026-11-04", "recent": "2026-11-17"}


def test_second_run_skips_everything_from_the_first(tmp_path):
    p = str(tmp_path / "sent.json")
    stories = [_story("https://a.example/1"), _story("https://b.example/2", cves=["CVE-2026-1"])]

    sent = state.load_sent(p)
    first = state.filter_unsent(stories, sent)
    assert first == stories
    for s in first:
        state.mark_sent(sent, state.story_keys(s), today=TODAY)
    state.save_sent(sent, path=p, today=TODAY)

    assert state.filter_unsent(stories, state.load_sent(p)) == []


def test_same_article_with_tracking_params_is_skipped():
    sent = state.mark_sent({}, state.story_keys(_story("https://a.example/post")), today=TODAY)
    again = _story("https://www.a.example/post/?utm_source=hn")
    assert state.is_sent(again, sent)


def test_new_article_about_an_already_sent_cve_is_skipped():
    sent = state.mark_sent({}, state.story_keys(_story("https://a.example/1", cves=["CVE-2026-1"])),
                           today=TODAY)
    follow_up = _story("https://b.example/different-article", cves=["CVE-2026-1"])
    assert state.is_sent(follow_up, sent)


def test_cve_comes_back_once_it_is_exploited():
    sent = state.mark_sent({}, state.story_keys(_story("https://a.example/1", cves=["CVE-2026-1"])),
                           today=TODAY)
    now_in_kev = _story("https://b.example/exploited", cves=["CVE-2026-1"], kev=["CVE-2026-1"])
    assert not state.is_sent(now_in_kev, sent)

    # After that goes out, a third article about it is skipped again.
    state.mark_sent(sent, state.story_keys(now_in_kev), today=TODAY)
    third = _story("https://c.example/more", cves=["CVE-2026-1"], kev=["CVE-2026-1"])
    assert state.is_sent(third, sent)


def test_story_with_one_new_cve_is_not_skipped():
    sent = state.mark_sent({}, {"cve:CVE-2026-1"}, today=TODAY)
    story = _story("https://b.example/two-bugs", cves=["CVE-2026-1", "CVE-2026-2"])
    assert not state.is_sent(story, sent)


def test_saved_file_is_sorted_json(tmp_path):
    p = tmp_path / "sent.json"
    state.save_sent({"b": "2026-11-17", "a": "2026-11-17"}, path=str(p), today=TODAY)
    assert list(json.loads(p.read_text())) == ["a", "b"]
    assert not (tmp_path / "sent.json.tmp").exists()
