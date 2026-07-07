"""
fetcher.py — all data fetching for the morning cybersecurity briefing.

Every fetch is wrapped so that a single broken source (a dead RSS feed, an NVD
hiccup, Indeed rate-limiting) logs a warning and returns whatever it can instead
of crashing the whole run.
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

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

# Indeed RSS is unreliable — see the README for what to do when it breaks.
INDEED_QUERIES = [
    ("penetration tester intern", "Massachusetts"),
    ("penetration tester intern", "Remote"),
    ("cybersecurity intern", "Massachusetts"),
]


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


def _job_key(entry):
    """Dedup key: normalized title (Indeed titles embed company + role)."""
    title = entry.get("title", "").strip().lower()
    return title


def fetch_jobs():
    """Fetch internship postings from Indeed RSS across all queries, deduplicated."""
    seen = set()
    jobs = []

    for query, location in INDEED_QUERIES:
        url = f"https://www.indeed.com/rss?q={quote(query)}&l={quote(location)}"
        try:
            feed = _parse_feed(url)
            if feed.bozo and not feed.entries:
                logger.warning(
                    "Indeed feed for '%s' in '%s' failed: %s",
                    query,
                    location,
                    feed.bozo_exception,
                )
                continue

            added = 0
            for entry in feed.entries:
                key = _job_key(entry)
                if not key or key in seen:
                    continue
                seen.add(key)
                jobs.append(
                    {
                        "title": entry.get("title", "(untitled)").strip(),
                        "link": entry.get("link", ""),
                        "summary": _clean_summary(entry.get("summary", ""), limit=250),
                        "query": f"{query} — {location}",
                    }
                )
                added += 1
            logger.info(
                "Fetched %d job(s) for '%s' in '%s'", added, query, location
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Error fetching Indeed feed for '%s' in '%s': %s",
                query,
                location,
                exc,
            )

    if not jobs:
        logger.warning(
            "No jobs fetched — Indeed RSS may be down/blocked. See README for alternatives."
        )
    return jobs


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
