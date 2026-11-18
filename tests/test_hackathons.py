"""Tests for hackathon parsing, filtering, and the sent log. No network."""

import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hackathons  # noqa: E402

TODAY = date(2026, 11, 18)


def _devpost(title, location="Online", dates="Dec 05 - 06, 2026", themes=(), regs=500):
    return {
        "title": title,
        "url": f"https://{title.lower().replace(' ', '')}.devpost.com/",
        "displayed_location": {
            "icon": "globe" if location == "Online" else "map-marker-alt",
            "location": location,
        },
        "submission_period_dates": dates,
        "themes": [{"name": t} for t in themes],
        "registrations_count": regs,
        "prize_amount": "$<span data-currency-value>10,000</span>",
    }


def _mlh(name, city, region, country="US", starts="2026-11-21T14:00:00Z", fmt="physical"):
    return {
        "name": name,
        "startsAt": starts,
        "endsAt": starts,
        "formatType": fmt,
        "websiteUrl": "https://example.org/",
        "url": "/events/x",
        "venueAddress": {"city": city, "state": region, "country": country},
        "customFields": {"hackathon_focus": ["Software"]},
    }


def _mlh_page(events):
    payload = json.dumps({"component": "SeasonEvents/Index", "props": {"upcomingEvents": events}})
    return f'<html><body><script data-page="app" type="application/json">{payload}</script></body></html>'


# --- location -----------------------------------------------------------------
def test_new_england_matches_states_codes_venues_and_typos():
    assert hackathons.in_new_england("Boston, MA")
    assert hackathons.in_new_england("Providence, RI")
    assert hackathons.in_new_england("Wellesley , Massachesetts")  # real MLH typo
    assert hackathons.in_new_england("WPI - Campus Center")  # Devpost venue-only
    assert hackathons.in_new_england("Boston University- CDS")


def test_new_england_rejects_lookalikes():
    assert not hackathons.in_new_england("Amherst, NY")  # UB Hacking
    assert not hackathons.in_new_england("Cambridge, UK")
    assert not hackathons.in_new_england("New Brunswick, NJ")
    assert not hackathons.in_new_england("Austin, TX, USA")
    assert not hackathons.in_new_england("Healey Family Student Center")  # Georgetown
    assert not hackathons.in_new_england("Summit Hall")  # "mit" inside a word
    assert not hackathons.in_new_england("")


def test_school_flag():
    h = {"name": "HackMIT 2027", "location": "Cambridge, MA"}
    assert hackathons.school_for(h) == "MIT"
    assert hackathons.school_for({"name": "Civic Hacks", "location": "Boston University"}) == \
        "Boston University"
    assert hackathons.school_for({"name": "Summit Hack", "location": "Hartford, CT"}) is None


# --- parsing ------------------------------------------------------------------
def test_devpost_date_formats():
    p = hackathons.parse_devpost_dates
    assert p("Nov 21, 2026") == (date(2026, 11, 21), date(2026, 11, 21))
    assert p("Nov 21 - 22, 2026") == (date(2026, 11, 21), date(2026, 11, 22))
    assert p("Oct 30 - Dec 04, 2026") == (date(2026, 10, 30), date(2026, 12, 4))
    assert p("Dec 19, 2026 - Jan 18, 2027") == (date(2026, 12, 19), date(2027, 1, 18))
    assert p("Dec 28 - Jan 03, 2027") == (date(2026, 12, 28), date(2027, 1, 3))
    assert p("TBD") == (None, None)


def test_parse_mlh_page_reads_embedded_json():
    events = hackathons.parse_mlh_page(_mlh_page([_mlh("BostonHacks", "Boston", "MA")]))
    assert events[0]["name"] == "BostonHacks"


def test_parse_mlh_page_fails_loudly_on_layout_change():
    try:
        hackathons.parse_mlh_page("<html><body>redesigned</body></html>")
    except ValueError as exc:
        assert "layout" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_mlh_country_check_blocks_cambridge_ontario():
    h = hackathons._normalize_mlh(_mlh("Hack Cambridge", "Cambridge", "Ontario", country="CA"))
    assert not h["new_england"]


def test_mlh_season_rolls_over_in_august():
    assert hackathons.mlh_url(date(2026, 7, 31)).endswith("/2026/events")
    assert hackathons.mlh_url(date(2026, 8, 1)).endswith("/2027/events")


def test_hostile_devpost_entry_is_sanitized():
    h = hackathons._normalize_devpost({**_devpost("Evil <img src=x>"), "url": "javascript:alert(1)"})
    assert "<img" not in h["name"] and h["url"] == ""


# --- selection ----------------------------------------------------------------
def _pool():
    mlh = [hackathons._normalize_mlh(e) for e in [
        _mlh("WHACK (Wellesley Hackathon)", "Wellesley ", "Massachesetts"),
        _mlh("Hack Western 13", "London", "Ontario", country="CA"),
        _mlh("Hoya Hacks", "Washington", "DC", starts="2027-01-22T14:00:00Z"),
    ]]
    devpost = [hackathons._normalize_devpost(e) for e in [
        _devpost("WHACK 2026", "Lulu Chow Wang Campus Center, Wellesley", "Nov 21 - 22, 2026"),
        _devpost("GoatHacks 2027", "WPI - Campus Center", "Mar 26 - 28, 2027"),
        _devpost("Global AI Builders", themes=["Machine Learning/AI"], regs=3000),
        _devpost("Design Jam", themes=["Design"], regs=5000),
        _devpost("Tiny AI Class Project", themes=["Machine Learning/AI"], regs=12),
        _devpost("Far Future Hacks", "Boston, MA", "Sep 03 - 05, 2027"),
        _devpost("Last Month Hacks", "Boston, MA", "Oct 01 - 02, 2026"),
    ]]
    return mlh + devpost


def test_select_filters_location_interest_and_dates():
    out = hackathons.select(_pool(), sent={}, today=TODAY)
    nearby = [h["name"] for h in out["nearby"]]
    online = [h["name"] for h in out["online"]]

    # Western is in Canada, Hoya in DC, Far Future past the horizon, Last Month
    # already over. GoatHacks (Mar 26) is 128 days out, also past the horizon.
    assert nearby == ["WHACK (Wellesley Hackathon)"]
    assert online == ["Global AI Builders"]  # Design Jam off-topic, tiny one too small

    # Once it is within the horizon, GoatHacks appears, sorted by start date.
    later = hackathons.select(_pool(), sent={}, today=date(2026, 11, 21))
    assert [h["name"] for h in later["nearby"]] == ["WHACK (Wellesley Hackathon)"]
    feb = hackathons.select(_pool(), sent={}, today=date(2027, 2, 1))
    assert [h["name"] for h in feb["nearby"]] == ["GoatHacks 2027"]


def test_select_dedups_across_sources_preferring_mlh():
    out = hackathons.select(_pool(), sent={}, today=TODAY)
    whack = [h for h in out["nearby"] if "WHACK" in h["name"]]
    assert len(whack) == 1 and whack[0]["source"] == "MLH"
    assert whack[0]["school"] == "Wellesley"


def test_sent_hackathon_skipped_until_it_is_starting_soon():
    pool = _pool()
    first = hackathons.select(pool, sent={}, today=date(2027, 3, 1))
    goat = next(h for h in first["nearby"] if h["name"] == "GoatHacks 2027")
    assert not goat["starting_soon"]
    sent = {k: "2027-03-01" for k in hackathons.hackathon_keys(goat)}

    # A week later, still weeks away: skipped.
    later = hackathons.select(pool, sent=sent, today=date(2027, 3, 8))
    assert "GoatHacks 2027" not in [h["name"] for h in later["nearby"]]

    # Within 7 days of the start: comes back once as a reminder.
    soon = hackathons.select(pool, sent=sent, today=date(2027, 3, 21))
    reminder = next(h for h in soon["nearby"] if h["name"] == "GoatHacks 2027")
    assert reminder["starting_soon"] and reminder["reminder"]

    # After the reminder is sent, it doesn't come back again.
    sent.update({k: "2027-03-21" for k in hackathons.hackathon_keys(reminder)})
    again = hackathons.select(pool, sent=sent, today=date(2027, 3, 22))
    assert "GoatHacks 2027" not in [h["name"] for h in again["nearby"]]


def test_online_cap():
    pool = [hackathons._normalize_devpost(
        _devpost(f"AI Hack {i}", themes=["Machine Learning/AI"], regs=1000 + i)) for i in range(10)]
    out = hackathons.select(pool, sent={}, today=TODAY)
    assert len(out["online"]) == hackathons.ONLINE_CAP
    assert out["online"][0]["name"] == "AI Hack 9"  # most registrations first
