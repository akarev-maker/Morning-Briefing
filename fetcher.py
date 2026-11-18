"""
fetcher.py: pull raw data from every outside source.

Each fetch function catches its own errors, logs a warning, and returns an
empty result. One broken source (a dead RSS feed, CISA having a bad day) costs
that one section, never the whole email.
"""

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests
from dateutil import parser as dateparser
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("briefing.fetcher")


def _make_session():
    """A requests Session that retries 429/5xx responses with backoff.

    Only GETs are retried (they are safe to repeat). A 404 is a real answer,
    not a transient failure, so it is returned immediately.
    """
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = _make_session()

# Some sources return 403 to feedparser's default client, so every request goes
# through `requests` with a browser-like User-Agent.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
FEED_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
}

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
CYBER_FEEDS = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

AI_FEEDS = {
    "OpenAI": "https://openai.com/news/rss.xml",
    "Google DeepMind": "https://deepmind.google/blog/rss.xml",
    "Hugging Face": "https://huggingface.co/blog/feed.xml",
    "Simon Willison": "https://simonwillison.net/atom/everything/",
    "MIT Technology Review": "https://www.technologyreview.com/topic/artificial-intelligence/feed",
}

# Every story that reached HN_MIN_POINTS, newest first. `newest` is used instead
# of `frontpage` because the front page is a snapshot: a story that peaked at
# 3 AM is already gone by the time the job runs.
HN_MIN_POINTS = 150
HN_FEED = f"https://hnrss.org/newest?points={HN_MIN_POINTS}&count=100"

# Hacker News covers everything, so its stories are sorted by title keywords.
# Matched as whole words, so "ai" does not match "again" or "said".
CYBER_KEYWORDS = (
    "security", "vulnerability", "vulnerabilities", "exploit", "exploited", "rce",
    "cve", "zero-day", "0day", "malware", "ransomware", "breach", "breached",
    "hacked", "hacker", "hackers", "phishing", "backdoor", "compromised",
    "skimmer", "infostealer", "botnet", "ddos", "spyware", "phrack", "cryptography",
    "encryption", "privilege escalation", "supply chain attack",
)
AI_KEYWORDS = (
    "ai", "llm", "llms", "gpt", "openai", "anthropic", "claude", "gemini",
    "deepmind", "mistral", "llama", "qwen", "deepseek", "hugging face",
    "machine learning", "deep learning", "neural", "transformer", "diffusion",
    "agent", "agents", "agentic", "inference", "fine-tuning", "reinforcement learning",
)


def _keyword_pattern(words):
    return re.compile(r"\b(" + "|".join(re.escape(w) for w in words) + r")\b", re.I)


_CYBER_RE = _keyword_pattern(CYBER_KEYWORDS)
_AI_RE = _keyword_pattern(AI_KEYWORDS)

# CISA's list of vulnerabilities confirmed exploited in the wild. One JSON file
# with the whole catalog (about 1,500 entries).
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Community index of public exploit repos on GitHub, one JSON file per CVE at
# /{year}/{CVE-ID}.json. 200 with a repo list if exploit code exists, 404 if not.
POC_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"

CTFTIME_URL = "https://ctftime.org/api/v1/events/"


# ---------------------------------------------------------------------------
# Sanitizing untrusted input
# ---------------------------------------------------------------------------
def _strip_html(text, limit=None):
    """Remove HTML tags and collapse whitespace.

    Everything from a feed is untrusted and ends up in an HTML email, so tags
    are removed at the point of entry.
    """
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", str(text))
    text = re.sub(r"\s+", " ", text).strip()
    if limit and len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def safe_url(url):
    """Return `url` if it is a plain http(s) URL, otherwise "".

    Blocks `javascript:` and `data:` links. Whitespace and control characters
    are removed before the check because browsers ignore them inside a scheme,
    so `java\\tscript:` would otherwise still work as a link.
    """
    cleaned = re.sub(r"[\s\x00-\x1f\x7f]+", "", str(url or ""))
    return cleaned if cleaned.lower().startswith(("http://", "https://")) else ""


# ---------------------------------------------------------------------------
# RSS news
# ---------------------------------------------------------------------------
def _parse_feed(url, timeout=30):
    """Download a feed with our headers and parse it. Raises on HTTP errors."""
    resp = SESSION.get(url, headers=FEED_HEADERS, timeout=timeout)
    resp.raise_for_status()
    return feedparser.parse(resp.content)


def _entry_datetime(entry):
    """Best-effort UTC publish time for a feed entry, or None."""
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        value = entry.get(key)
        if value:
            try:
                return datetime.fromtimestamp(time.mktime(value), tz=timezone.utc)
            except (OverflowError, ValueError):
                pass
    for key in ("published", "updated", "created"):
        value = entry.get(key)
        if value:
            try:
                dt = dateparser.parse(value)
                if dt is not None:
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
            except (ValueError, TypeError, OverflowError):
                pass
    return None


def story_id(url, title=""):
    """A short, stable ID for a story, from its URL (or title if it has none).

    The model is given these IDs and must answer with them, so it can only pick
    stories that exist. Tracking parameters and trailing slashes are removed so
    the same article linked two ways gets the same ID.
    """
    key = (url or "").strip().lower()
    key = re.sub(r"^https?://(www\.)?", "", key)
    key = re.sub(r"#.*$", "", key)
    key = re.sub(r"[?&]utm_[^&]*", "", key).rstrip("?&/")
    return hashlib.sha1((key or title.lower()).encode("utf-8")).hexdigest()[:10]


def classify_title(title):
    """'cyber', 'ai', or None, by keyword. Cyber wins when both match, since
    "AI-written malware" is a security story first."""
    if _CYBER_RE.search(title):
        return "cyber"
    if _AI_RE.search(title):
        return "ai"
    return None


def _fetch_feeds(feeds, category, hours):
    """Items from the last `hours` across `feeds`. Undated items are kept."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    items = []

    for source, url in feeds.items():
        try:
            feed = _parse_feed(url)
            if feed.bozo and not feed.entries:
                logger.warning("Feed '%s' failed to parse: %s", source, feed.bozo_exception)
                continue

            kept = 0
            for entry in feed.entries:
                published = _entry_datetime(entry)
                if published is not None and published < cutoff:
                    continue
                items.append(
                    _story(
                        source=source,
                        category=category,
                        title=entry.get("title", "(untitled)"),
                        link=entry.get("link", ""),
                        summary=entry.get("summary", ""),
                        published=published,
                    )
                )
                kept += 1
            logger.info("Fetched %d recent item(s) from %s", kept, source)
        except Exception as exc:  # noqa: BLE001 - one bad feed must not kill the run
            logger.warning("Error fetching feed '%s': %s", source, exc)

    return items


def _story(source, category, title, link, summary, published, points=None, comments=""):
    """The one shape every story has, whatever feed it came from."""
    title = _strip_html(title)
    link = safe_url(link)
    return {
        "id": story_id(link, title),
        "source": source,
        "category": category,
        "title": title,
        "link": link,
        "summary": _strip_html(summary, limit=400),
        "published": published.isoformat() if published else "",
        "points": points,
        "comments": safe_url(comments),
    }


def fetch_rss_feeds(hours=24):
    """Recent stories from the security and AI feeds, labeled by category."""
    return _fetch_feeds(CYBER_FEEDS, "cyber", hours) + _fetch_feeds(AI_FEEDS, "ai", hours)


_HN_POINTS_RE = re.compile(r"Points:\s*(\d+)")


def _hn_story(entry):
    """Turn one hnrss entry into a story, or None if it isn't cyber or AI.

    hnrss puts the score in the description ("Points: 386"); the description
    has no real summary, so it is dropped.
    """
    title = entry.get("title", "")
    category = classify_title(title)
    if category is None:
        return None
    match = _HN_POINTS_RE.search(entry.get("summary", "") or "")
    return _story(
        source="Hacker News",
        category=category,
        title=title,
        link=entry.get("link", ""),
        summary="",
        published=_entry_datetime(entry),
        points=int(match.group(1)) if match else None,
        comments=entry.get("comments", ""),
    )


def fetch_hn(hours=24):
    """Popular Hacker News stories from the last `hours` that are cyber or AI."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    try:
        feed = _parse_feed(HN_FEED)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching Hacker News: %s", exc)
        return []

    stories, skipped = [], 0
    for entry in feed.entries:
        published = _entry_datetime(entry)
        if published is not None and published < cutoff:
            continue
        story = _hn_story(entry)
        if story is None:
            skipped += 1
        else:
            stories.append(story)
    logger.info(
        "Fetched %d Hacker News stor%s (%d off-topic skipped)",
        len(stories), "y" if len(stories) == 1 else "ies", skipped,
    )
    return stories


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------
def fetch_kev():
    """The full KEV catalog as {cve_id: entry}. Empty dict on failure.

    The whole catalog is kept (not just recent additions) because a news story
    can be about a CVE that was added to KEV months ago.
    """
    try:
        resp = SESSION.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=40)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching CISA KEV catalog: %s", exc)
        return {}

    catalog = {}
    for vuln in payload.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        catalog[cve_id] = {
            "id": cve_id,
            "name": _strip_html(vuln.get("vulnerabilityName", "")),
            "date_added": vuln.get("dateAdded", ""),
            "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
        }
    logger.info("Loaded %d KEV entries", len(catalog))
    return catalog


# ---------------------------------------------------------------------------
# Public exploit lookup (PoC-in-GitHub)
# ---------------------------------------------------------------------------
def pocs_for_cve(cve_id, session=SESSION):
    """Up to 3 public exploit repos for a CVE, most-starred first. [] if none."""
    parts = cve_id.split("-")
    if len(parts) < 3 or not parts[1].isdigit():
        return []
    url = f"{POC_BASE}/{parts[1]}/{cve_id}.json"
    try:
        resp = session.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        repos = resp.json()
    except Exception:  # noqa: BLE001 - extra info, never worth failing over
        return []
    repos = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
    pocs = []
    for r in repos[:3]:
        url = safe_url(r.get("html_url", ""))
        if url:
            pocs.append({"url": url, "stars": r.get("stargazers_count", 0)})
    return pocs


# ---------------------------------------------------------------------------
# CTFtime
# ---------------------------------------------------------------------------
def _parse_ctf_events(events):
    """Normalize raw CTFtime events, soonest first. No network."""
    parsed = []
    for e in events:
        parsed.append(
            {
                "title": _strip_html(e.get("title", "")),
                "start": e.get("start", ""),
                "finish": e.get("finish", ""),
                # Event homepages are user-submitted. If the URL is unsafe, fall
                # back to the event's CTFtime page instead of dropping the link.
                "url": safe_url(e.get("url")) or safe_url(e.get("ctftime_url")),
                "format": _strip_html(e.get("format", "")),
                "onsite": bool(e.get("onsite", False)),
                "location": _strip_html(e.get("location", ""))
                or ("On-site" if e.get("onsite") else "Online"),
                "weight": e.get("weight", 0) or 0,
            }
        )
    parsed.sort(key=lambda x: x["start"])
    return parsed


def fetch_ctf_events(limit=8, weeks_ahead=3):
    """Upcoming CTFs from CTFtime's public API."""
    now = datetime.now(timezone.utc)
    params = {
        "limit": 100,
        "start": int(now.timestamp()),
        "finish": int((now + timedelta(weeks=weeks_ahead)).timestamp()),
    }
    try:
        resp = SESSION.get(
            CTFTIME_URL, params=params, headers={"User-Agent": USER_AGENT}, timeout=30
        )
        resp.raise_for_status()
        events = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching CTFtime events: %s", exc)
        return []

    result = _parse_ctf_events(events)[:limit]
    logger.info("Fetched %d upcoming CTF event(s)", len(result))
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def fetch_all():
    """Fetch every source. Never raises; a failed source comes back empty."""
    logger.info("Starting data fetch…")
    data = {
        "news": fetch_rss_feeds() + fetch_hn(),
        "kev": fetch_kev(),
        "ctf": fetch_ctf_events(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    by_cat = {c: sum(1 for s in data["news"] if s["category"] == c) for c in ("cyber", "ai")}
    logger.info(
        "Fetch complete: %d cyber + %d AI stories, %d KEV entries, %d CTFs",
        by_cat["cyber"],
        by_cat["ai"],
        len(data["kev"]),
        len(data["ctf"]),
    )
    return data


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    out = fetch_all()
    out["kev"] = f"<{len(out['kev'])} entries>"  # the full catalog is too long to print
    print(json.dumps(out, indent=2)[:5000])
