"""
fetcher.py — all data fetching for the morning cybersecurity briefing.

Every fetch is wrapped so that a single broken source (a dead RSS feed, an NVD
hiccup, Indeed rate-limiting) logs a warning and returns whatever it can instead
of crashing the whole run.
"""

import logging
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests
from dateutil import parser as dateparser

logger = logging.getLogger("briefing.fetcher")

# A browser-like User-Agent keeps feeds/APIs from rejecting us. feedparser's own
# HTTP client gets a 403 from some sources (e.g. CISA behind its CDN), so we fetch
# every feed through `requests` with these headers and hand the bytes to feedparser.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
FEED_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
}


def _parse_feed(url, timeout=30):
    """Fetch a feed URL via requests (controlled headers) and parse it.

    Returns a feedparser result. Raises on a non-2xx HTTP status so the caller's
    try/except can log and move on.
    """
    resp = requests.get(url, headers=FEED_HEADERS, timeout=timeout)
    resp.raise_for_status()
    return feedparser.parse(resp.content)

# ---------------------------------------------------------------------------
# RSS news feeds
# ---------------------------------------------------------------------------
RSS_FEEDS = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Curated, community-maintained internship lists on GitHub. They publish
# structured JSON updated daily and are served from raw.githubusercontent.com,
# so (unlike Indeed RSS) they are never IP-blocked from GitHub Actions runners.
# We pull from both the current and next Summer cycle so the source stays useful
# year-round as repos roll over. See the README for swapping these when a new
# cycle's repo appears.
INTERNSHIP_SOURCES = [
    (
        "Summer 2026",
        "https://raw.githubusercontent.com/SimplifyJobs/Summer2026-Internships/dev/.github/scripts/listings.json",
    ),
    (
        "Summer 2027",
        "https://raw.githubusercontent.com/vanshb03/Summer2027-Internships/dev/.github/scripts/listings.json",
    ),
]

# A role counts as security-relevant if its title contains any of these.
SECURITY_KEYWORDS = (
    "security",
    "cyber",
    "penetration",
    "pentest",
    "pen test",
    "red team",
    "appsec",
    "infosec",
    "soc analyst",
    "malware",
    "vulnerability",
    "incident response",
    "threat",
)


def _entry_datetime(entry):
    """Best-effort published/updated timestamp for an RSS entry (UTC aware)."""
    # Prefer the pre-parsed struct_time feedparser gives us.
    for parsed_key in ("published_parsed", "updated_parsed", "created_parsed"):
        value = entry.get(parsed_key)
        if value:
            try:
                return datetime.fromtimestamp(time.mktime(value), tz=timezone.utc)
            except (OverflowError, ValueError):
                pass
    # Fall back to parsing the raw string.
    for str_key in ("published", "updated", "created"):
        value = entry.get(str_key)
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


def _clean_summary(text, limit=400):
    """Strip HTML tags and squash whitespace from an RSS summary."""
    if not text:
        return ""
    # Cheap tag stripping — good enough for feeding a language model.
    import re

    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def fetch_rss_feeds(hours=24):
    """Return recent (last `hours`) items across all configured news feeds."""
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
                # If we cannot date an entry, keep it only when the feed is small,
                # otherwise assume it is old and skip it.
                if published is not None and published < cutoff:
                    continue
                items.append(
                    {
                        "source": source,
                        "title": entry.get("title", "(untitled)").strip(),
                        "link": entry.get("link", ""),
                        "summary": _clean_summary(entry.get("summary", "")),
                        "published": published.isoformat() if published else "",
                    }
                )
                kept += 1
            logger.info("Fetched %d recent item(s) from %s", kept, source)
        except Exception as exc:  # noqa: BLE001 — one bad feed must not kill the run
            logger.warning("Error fetching feed '%s': %s", source, exc)

    return items


def _extract_cvss(cve):
    """Return (score, severity, vector) from an NVD CVE object, newest metric first."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = (
                data.get("baseSeverity")
                or entries[0].get("baseSeverity")
                or ""
            )
            vector = data.get("vectorString", "")
            if score is not None:
                return float(score), severity, vector
    return None, "", ""


def _english_description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def fetch_cves(hours=24, min_cvss=7.0, cap=40):
    """Fetch CVEs published in the last `hours`, sorted by CVSS score descending.

    High-severity (>= `min_cvss`) CVEs are prioritized; if fewer than a handful
    of those exist we backfill with lower-scored ones so the section is not empty.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {
        # NVD wants ISO-8601; no offset is interpreted as UTC.
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }

    try:
        resp = requests.get(
            NVD_URL,
            params=params,
            headers={"User-Agent": USER_AGENT},
            timeout=40,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching CVEs from NVD: %s", exc)
        return []

    parsed = []
    for vuln in payload.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        score, severity, vector = _extract_cvss(cve)
        parsed.append(
            {
                "id": cve.get("id", "UNKNOWN"),
                "score": score if score is not None else 0.0,
                "severity": severity,
                "vector": vector,
                "description": _english_description(cve),
                "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
            }
        )

    parsed.sort(key=lambda c: c["score"], reverse=True)

    high = [c for c in parsed if c["score"] >= min_cvss]
    if len(high) >= 5:
        result = high[:cap]
    else:
        # Not many high-severity ones today — include the top of the list anyway.
        result = parsed[:cap]

    logger.info(
        "Fetched %d CVE(s) (%d at CVSS >= %.1f)", len(result), len(high), min_cvss
    )
    return result


def _is_security_role(title):
    return any(keyword in title.lower() for keyword in SECURITY_KEYWORDS)


def _location_rank(locations):
    """0 = Massachusetts, 1 = remote, 2 = everywhere else. Lower sorts first.

    The recipient is MA-based and open to remote, so those surface at the top.
    """
    joined = " ".join(locations).lower()
    if any(city in joined for city in ("massachusetts", "boston", "cambridge")):
        return 0
    # Match the ", MA" state code without catching substrings like 'Norman'.
    for loc in locations:
        tokens = [t.strip().lower() for t in loc.replace("/", ",").split(",")]
        if "ma" in tokens:
            return 0
    if "remote" in joined:
        return 1
    return 2


def fetch_jobs(cap=25):
    """Fetch active cybersecurity internships from curated GitHub listing repos.

    Filters to active security-relevant roles, deduplicates across sources, and
    sorts so Massachusetts and remote roles surface first (then newest).
    """
    seen = set()
    jobs = []

    for label, url in INTERNSHIP_SOURCES:
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=40)
            resp.raise_for_status()
            listings = resp.json()
        except Exception as exc:  # noqa: BLE001 — one bad source must not kill the run
            logger.warning("Error fetching internship source '%s': %s", label, exc)
            continue

        added = 0
        for item in listings:
            if not item.get("active"):
                continue
            title = item.get("title", "")
            if not _is_security_role(title):
                continue
            key = item.get("id") or item.get("url")
            if not key or key in seen:
                continue
            seen.add(key)

            locations = item.get("locations") or []
            terms = item.get("terms") or [label]
            jobs.append(
                {
                    "title": title.strip(),
                    "company": (item.get("company_name") or "").strip(),
                    "link": item.get("url", ""),
                    "locations": locations,
                    "location_str": ", ".join(locations) if locations else "Unspecified",
                    "term": terms[0],
                    "rank": _location_rank(locations),
                    "date_posted": item.get("date_posted") or 0,
                }
            )
            added += 1
        logger.info("Fetched %d active security internship(s) from %s", added, label)

    # Massachusetts first, then remote, then the rest; newest within each group.
    jobs.sort(key=lambda j: (j["rank"], -j["date_posted"]))
    result = jobs[:cap]

    if not result:
        logger.warning(
            "No active security internships found in curated sources today. "
            "See README for swapping in a newer cycle's repo."
        )
    return result


def fetch_all():
    """Fetch everything, returning a single dict. Never raises."""
    logger.info("Starting data fetch…")
    data = {
        "news": fetch_rss_feeds(),
        "cves": fetch_cves(),
        "jobs": fetch_jobs(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(
        "Fetch complete: %d news, %d cves, %d jobs",
        len(data["news"]),
        len(data["cves"]),
        len(data["jobs"]),
    )
    return data


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    import json

    print(json.dumps(fetch_all(), indent=2)[:5000])
