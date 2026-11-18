"""
fetcher.py: pull raw data from every outside source.

Each fetch function catches its own errors, logs a warning, and returns an
empty result. One broken source (a dead RSS feed, CISA having a bad day) costs
that one section, never the whole email.
"""

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
RSS_FEEDS = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

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


def fetch_rss_feeds(hours=24):
    """Items from the last `hours` across all feeds. Undated items are kept."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    items = []

    for source, url in RSS_FEEDS.items():
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
                    {
                        "source": source,
                        "title": _strip_html(entry.get("title", "(untitled)")),
                        "link": safe_url(entry.get("link", "")),
                        "summary": _strip_html(entry.get("summary", ""), limit=400),
                        "published": published.isoformat() if published else "",
                    }
                )
                kept += 1
            logger.info("Fetched %d recent item(s) from %s", kept, source)
        except Exception as exc:  # noqa: BLE001 - one bad feed must not kill the run
            logger.warning("Error fetching feed '%s': %s", source, exc)

    return items


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
        "news": fetch_rss_feeds(),
        "kev": fetch_kev(),
        "ctf": fetch_ctf_events(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(
        "Fetch complete: %d news, %d KEV entries, %d CTFs",
        len(data["news"]),
        len(data["kev"]),
        len(data["ctf"]),
    )
    return data


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    out = fetch_all()
    out["kev"] = f"<{len(out['kev'])} entries>"  # the full catalog is too long to print
    print(json.dumps(out, indent=2)[:5000])
