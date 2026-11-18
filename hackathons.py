"""
hackathons.py: upcoming hackathons worth knowing about.

Two sources:
  - Devpost: a JSON API (the one devpost.com's own search page calls).
  - MLH: no API. Its events page is server-rendered, but the event data is
    embedded in the page as JSON (<script data-page="app">), so we parse that
    instead of the visible HTML. Fields like `startsAt` and `venueAddress` are
    far less likely to change than CSS classes.

What makes the cut:
  - In-person events in New England, whatever the topic ("close to me").
  - Online events tagged AI/ML or security, biggest first, a few per day.
Events at schools in GOOD_SCHOOLS are flagged "worth applying".
"""

import json
import logging
import re
from datetime import date, datetime, timedelta

from bs4 import BeautifulSoup

import fetcher
import state

logger = logging.getLogger("briefing.hackathons")

DEVPOST_URL = "https://devpost.com/api/hackathons"
DEVPOST_MAX_PAGES = 25  # 9 events per page; about 160 upcoming events in total

# Only events starting within this many days are shown, so each one first
# appears with enough lead time to register, not five months out.
HORIZON_DAYS = 120
# An event that was already sent comes back once when it is this close.
STARTING_SOON_DAYS = 7
# Online events: at most this many per email, and only ones with enough
# sign-ups to be real (Devpost lists class assignments and "test" events).
ONLINE_CAP = 4
ONLINE_MIN_REGISTRATIONS = 100

INTEREST_THEMES = {"Machine Learning/AI", "Cybersecurity"}

# Edit freely. Each school maps to the patterns that identify it in an event's
# name or location. Matched as whole words, so "mit" doesn't match "summit".
GOOD_SCHOOLS = {
    "MIT": ["mit", "hackmit", "massachusetts institute of technology"],
    "Harvard": ["harvard", "hackharvard"],
    "Brown": ["brown university", "hack@brown"],
    "Yale": ["yale", "yhack"],
    "Dartmouth": ["dartmouth", "hackdartmouth"],
    "Tufts": ["tufts", "jumbohack"],
    "Northeastern": ["northeastern"],
    "Boston University": ["boston university", "bostonhacks"],
    "WPI": ["wpi", "worcester polytechnic", "goathacks"],
    "Wellesley": ["wellesley"],
    "UMass": ["umass", "hackumass"],
}

# Matched against free-text locations. Devpost locations are often just a
# venue ("WPI - Campus Center"), so schools and cities are needed, not only
# state names. MLH's data has typos, hence the misspellings of Massachusetts.
NEW_ENGLAND_STATES = {
    "massachusetts", "massachesetts", "massachusets", "massachussetts",
    "rhode island", "connecticut", "new hampshire", "vermont", "maine",
}
NEW_ENGLAND_ABBREVIATIONS = {"ma", "ri", "ct", "nh", "vt", "me"}
NEW_ENGLAND_PLACES = {
    "boston", "cambridge", "amherst", "worcester", "providence", "new haven",
    "hartford", "wellesley", "medford", "somerville", "waltham", "lowell",
    "northampton", "storrs", "middlebury",
    "mit", "harvard", "tufts", "northeastern", "wpi", "umass", "brandeis",
    "babson", "bentley", "olin college", "brown university", "risd", "yale",
    "uconn", "wesleyan", "dartmouth", "uvm", "unh", "bowdoin", "colby", "bates",
    "smith college", "williams college",
}
# Places that share a name with somewhere above: Amherst NY (UB Hacking),
# Cambridge UK and Ontario, New Brunswick NJ (HackRU). Any of these in the
# location overrides a match.
NOT_NEW_ENGLAND = {
    "new york", "ny", "new jersey", "nj", "uk", "united kingdom", "canada",
    "ontario", "australia",
}


def _word_pattern(words):
    alternatives = "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))
    return re.compile(rf"(?<![a-z0-9])({alternatives})(?![a-z0-9])", re.IGNORECASE)


_NE_PLACE_RE = _word_pattern(NEW_ENGLAND_STATES | NEW_ENGLAND_PLACES)
_NOT_NE_RE = _word_pattern(NOT_NEW_ENGLAND)
_SCHOOL_RES = {school: _word_pattern(patterns) for school, patterns in GOOD_SCHOOLS.items()}


def in_new_england(location):
    """True if a free-text location looks like it is in New England."""
    if not location or _NOT_NE_RE.search(location):
        return False
    if _NE_PLACE_RE.search(location):
        return True
    # State codes only count as their own comma-separated part ("Boston, MA"),
    # so "ME" or "MA" inside a word or sentence doesn't match.
    parts = [p.strip().lower() for p in re.split(r"[,/]", location)]
    return any(p in NEW_ENGLAND_ABBREVIATIONS for p in parts)


def school_for(hackathon):
    """The GOOD_SCHOOLS name hosting this event, or None."""
    text = f"{hackathon['name']} {hackathon['location']}"
    for school, pattern in _SCHOOL_RES.items():
        if pattern.search(text):
            return school
    return None


def _name_key(name):
    """Normalize a name so one event listed on both sites matches:
    "BostonHacks 2026" and "BostonHacks" -> "bostonhacks"."""
    name = re.sub(r"\(.*?\)", "", name.lower())  # "WHACK (Wellesley Hackathon)"
    name = re.sub(r"\b20\d\d\b", "", name)
    return re.sub(r"[^a-z0-9]", "", name)


# ---------------------------------------------------------------------------
# Devpost
# ---------------------------------------------------------------------------
def parse_devpost_dates(text):
    """(start, end) dates from Devpost's display string, or (None, None).

    Formats seen: "Nov 21, 2026", "Nov 21 - 22, 2026", "Oct 30 - Dec 04, 2026",
    "Dec 19, 2026 - Jan 18, 2027". These are the submission dates; for an
    in-person event that is the event itself.
    """
    fmt = "%b %d, %Y"
    parts = [p.strip() for p in (text or "").split(" - ")]
    try:
        if len(parts) == 1:
            day = datetime.strptime(parts[0], fmt).date()
            return day, day
        left, right = parts[0], parts[1]
        if not right[:1].isalpha():  # "22, 2026": same month as the start
            right = f"{left.split()[0]} {right}"
        end = datetime.strptime(right, fmt).date()
        if re.search(r"\d{4}$", left):
            start = datetime.strptime(left, fmt).date()
        else:
            start = datetime.strptime(f"{left}, {end.year}", fmt).date()
            if start > end:  # "Dec 28 - Jan 03, 2027" crosses a year
                start = start.replace(year=end.year - 1)
        return start, end
    except (ValueError, IndexError):
        return None, None


def _normalize_devpost(item):
    start, end = parse_devpost_dates(item.get("submission_period_dates", ""))
    where = item.get("displayed_location") or {}
    location = fetcher._strip_html(where.get("location", ""))
    online = where.get("icon") == "globe" or location.lower() in ("online", "virtual")
    prize = fetcher._strip_html(item.get("prize_amount", ""))
    return {
        "key": _name_key(item.get("title", "")),
        "name": fetcher._strip_html(item.get("title", "")),
        "url": fetcher.safe_url(item.get("url", "")),
        "start": start,
        "end": end,
        "location": "Online" if online else location,
        "online": online,
        "new_england": not online and in_new_england(location),
        "themes": [t.get("name", "") for t in item.get("themes", [])],
        "registrations": item.get("registrations_count") or 0,
        "prize": "" if prize in ("", "$0") else prize,
        "source": "Devpost",
    }


def fetch_devpost(max_pages=DEVPOST_MAX_PAGES):
    """Every upcoming or open Devpost hackathon. Keeps whatever pages loaded."""
    items = []
    for page in range(1, max_pages + 1):
        try:
            resp = fetcher.SESSION.get(
                DEVPOST_URL,
                params={"status[]": ["upcoming", "open"], "page": page},
                headers={"User-Agent": fetcher.USER_AGENT},
                timeout=20,
            )
            resp.raise_for_status()
            batch = resp.json().get("hackathons", [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error fetching Devpost page %d: %s", page, exc)
            break
        if not batch:
            break
        items.extend(batch)
    logger.info("Fetched %d Devpost hackathon(s)", len(items))
    return [_normalize_devpost(i) for i in items]


# ---------------------------------------------------------------------------
# MLH
# ---------------------------------------------------------------------------
def mlh_url(today=None):
    """MLH seasons run August to July and are named for the year they end."""
    today = today or date.today()
    season = today.year + 1 if today.month >= 8 else today.year
    return f"https://www.mlh.com/seasons/{season}/events"


def parse_mlh_page(html):
    """Raw event dicts from the JSON embedded in an MLH events page."""
    tag = BeautifulSoup(html, "html.parser").find("script", attrs={"data-page": "app"})
    if tag is None or not tag.string:
        raise ValueError("MLH page has no embedded event data (layout changed?)")
    return json.loads(tag.string).get("props", {}).get("upcomingEvents", [])


def _iso_date(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _normalize_mlh(item):
    venue = item.get("venueAddress") or {}
    city = (venue.get("city") or "").strip()
    region = (venue.get("state") or "").strip()
    online = item.get("formatType") == "digital"
    location = "Online" if online else ", ".join(p for p in (city, region) if p)
    url = fetcher.safe_url(item.get("websiteUrl")) or fetcher.safe_url(
        "https://www.mlh.com" + (item.get("url") or "")
    )
    return {
        "key": _name_key(item.get("name", "")),
        "name": fetcher._strip_html(item.get("name", "")),
        "url": url,
        "start": _iso_date(item.get("startsAt")),
        "end": _iso_date(item.get("endsAt")),
        "location": fetcher._strip_html(location),
        "online": online,
        # MLH gives a country, so "Cambridge, Ontario" can't slip through.
        "new_england": not online and venue.get("country") == "US"
        and in_new_england(location),
        "themes": (item.get("customFields") or {}).get("hackathon_focus") or [],
        "registrations": None,
        "prize": "",
        "source": "MLH",
    }


def fetch_mlh(today=None):
    """MLH's next ~24 upcoming events (one page; MLH ignores ?page=)."""
    try:
        resp = fetcher.SESSION.get(
            mlh_url(today), headers={"User-Agent": fetcher.USER_AGENT}, timeout=20
        )
        resp.raise_for_status()
        events = parse_mlh_page(resp.text)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching MLH events: %s", exc)
        return []
    logger.info("Fetched %d MLH event(s)", len(events))
    return [_normalize_mlh(e) for e in events]


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
def _matches_interests(hackathon):
    if INTEREST_THEMES & set(hackathon["themes"]):
        return True
    return fetcher.classify_title(hackathon["name"]) is not None


def hackathon_keys(hackathon):
    """Sent-log keys for a hackathon that is about to go out."""
    keys = {f"hackathon:{hackathon['key']}"}
    if hackathon.get("starting_soon"):
        keys.add(f"hackathon-soon:{hackathon['key']}")
    return keys


def select(hackathons, sent, today=None):
    """Pick what goes in today's email. Returns {"nearby": [...], "online": [...]}.

    Order of filters: drop past/far-off events, keep New England in-person or
    on-topic online, de-duplicate across sources, then drop anything already
    sent (unless it now starts within STARTING_SOON_DAYS).
    """
    today = today or date.today()
    horizon = today + timedelta(days=HORIZON_DAYS)

    picked, seen = [], set()
    # MLH first: when an event is on both sites, keep MLH's structured copy.
    for h in sorted(hackathons, key=lambda h: h["source"] != "MLH"):
        if not h["start"] or not h["key"] or h["key"] in seen:
            continue
        if (h["end"] or h["start"]) < today or h["start"] > horizon:
            continue
        if h["online"]:
            if not _matches_interests(h) or (h["registrations"] or 0) < ONLINE_MIN_REGISTRATIONS:
                continue
        elif not h["new_england"]:
            continue

        days_away = (h["start"] - today).days
        soon = 0 <= days_away <= STARTING_SOON_DAYS
        if f"hackathon:{h['key']}" in sent:
            if not soon or f"hackathon-soon:{h['key']}" in sent:
                continue
            h = {**h, "reminder": True}
        seen.add(h["key"])
        picked.append({**h, "starting_soon": soon, "school": school_for(h)})

    nearby = sorted((h for h in picked if not h["online"]), key=lambda h: h["start"])
    online = sorted(
        (h for h in picked if h["online"]), key=lambda h: h["registrations"] or 0, reverse=True
    )[:ONLINE_CAP]
    logger.info("Selected %d nearby and %d online hackathon(s)", len(nearby), len(online))
    return {"nearby": nearby, "online": online}


def fetch_hackathons():
    """All normalized hackathons from both sources. Never raises."""
    return fetch_mlh() + fetch_devpost()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    chosen = select(fetch_hackathons(), state.load_sent())
    for group in ("nearby", "online"):
        print(f"\n== {group} ==")
        for h in chosen[group]:
            flags = [f for f, on in (
                (f"worth applying ({h['school']})", h["school"]),
                ("starting soon", h["starting_soon"]),
                ("reminder", h.get("reminder")),
            ) if on]
            print(f"  {h['start']}  {h['name'][:40]:40}  {h['location'][:30]:30}  "
                  f"[{h['source']}] {', '.join(flags)}")
