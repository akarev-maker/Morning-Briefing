"""
fetcher.py — all data fetching for the morning cybersecurity briefing.

Every fetch is wrapped so that a single broken source (a dead RSS feed, an NVD
hiccup, Indeed rate-limiting) logs a warning and returns whatever it can instead
of crashing the whole run.
"""

import json
import logging
import os
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
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CISA's advisory RSS is IP-blocked (403) from GitHub Actions runners. We instead
# use CISA's Known Exploited Vulnerabilities (KEV) catalog — plain JSON, never
# blocked, and arguably more actionable: every entry is confirmed exploited in
# the wild, so it matters regardless of CVSS score.
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Upcoming CTF competitions (great for skill-building + résumé). Public JSON API.
CTFTIME_URL = "https://ctftime.org/api/v1/events/"

# Community index mapping CVEs -> public proof-of-concept exploit repos on GitHub.
# Per-CVE JSON at /{year}/{CVE-ID}.json (200 with repo list, 404 if none). Lets us
# flag which CVEs are actually weaponized — exactly how a pentester triages.
POC_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"

# HackTheBox API (needs a personal App Token — optional; skipped if unset).
HTB_API = "https://labs.hackthebox.com/api/v4"

# USAJOBS federal job search (needs a free API key — optional; skipped if unset).
# This is where MA-area federal/defense cyber internships live (Lincoln Lab,
# national labs, DoD, etc.).
USAJOBS_URL = "https://data.usajobs.gov/api/search"
# Federal internships are mostly "Student Trainee" / Pathways roles, not "intern",
# so we search for both framings.
USAJOBS_QUERIES = [
    ("penetration tester intern", None),
    ("cybersecurity intern", "Massachusetts"),
    ("cybersecurity student trainee", None),
    ("information technology student trainee", "Massachusetts"),
]
# A federal posting counts as an internship if its title has any of these.
USAJOBS_INTERN_HINTS = ("intern", "student trainee", "pathways")

# Where we remember which internships we've already seen, so we can flag the ones
# that are brand-new since yesterday. Committed back to the repo by the workflow.
STATE_DIR = "state"
SEEN_JOBS_PATH = os.path.join(STATE_DIR, "seen_jobs.json")

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


def fetch_kev(days=7, cap=15):
    """Fetch CVEs recently added to CISA's Known Exploited Vulnerabilities catalog.

    These are confirmed actively exploited in the wild — high priority regardless
    of CVSS. CISA adds them in irregular batches, so we use a `days`-wide window
    (not just 24h) to keep the section meaningful, newest first.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date()
    try:
        resp = requests.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=40)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching CISA KEV feed: %s", exc)
        return []

    recent = []
    for vuln in payload.get("vulnerabilities", []):
        date_str = vuln.get("dateAdded", "")
        try:
            added = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            continue
        if added < cutoff:
            continue
        cve_id = vuln.get("cveID", "")
        recent.append(
            {
                "id": cve_id,
                "name": vuln.get("vulnerabilityName", ""),
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "description": vuln.get("shortDescription", ""),
                "date_added": date_str,
                "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )

    recent.sort(key=lambda k: k["date_added"], reverse=True)
    result = recent[:cap]
    logger.info(
        "Fetched %d KEV entr%s added in the last %d days",
        len(result),
        "y" if len(result) == 1 else "ies",
        days,
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


def fetch_jobs(cap=40):
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
            degrees = item.get("degrees") or []
            jobs.append(
                {
                    "title": title.strip(),
                    "company": (item.get("company_name") or "").strip(),
                    "link": item.get("url", ""),
                    "locations": locations,
                    "location_str": ", ".join(locations) if locations else "Unspecified",
                    "term": terms[0],
                    "category": (item.get("category") or "").strip(),
                    "sponsorship": (item.get("sponsorship") or "").strip(),
                    "degrees": degrees,
                    "date_posted": item.get("date_posted") or 0,
                    "rank": _location_rank(locations),
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


def _normalize_usajobs_item(descriptor):
    locations = [
        loc.get("LocationName", "")
        for loc in descriptor.get("PositionLocation", [])
        if loc.get("LocationName")
    ]
    date_posted = 0
    start = descriptor.get("PublicationStartDate", "")
    if start:
        try:
            date_posted = int(dateparser.parse(start).timestamp())
        except (ValueError, TypeError, OverflowError):
            date_posted = 0
    return {
        "title": descriptor.get("PositionTitle", "").strip(),
        "company": (descriptor.get("OrganizationName") or "").strip(),
        "link": descriptor.get("PositionURI", ""),
        "locations": locations,
        "location_str": ", ".join(locations) if locations else "Unspecified",
        "term": "Federal",
        "category": "Government / Federal",
        "sponsorship": "U.S. Citizenship typically required",
        "degrees": [],
        "date_posted": date_posted,
        "rank": _location_rank(locations),
        "source": "USAJOBS",
    }


def fetch_usajobs():
    """Fetch federal cyber internships from USAJOBS (optional; needs a free key).

    Skipped silently if USAJOBS_API_KEY / USAJOBS_EMAIL aren't set. This surfaces
    the MA-area federal/defense internships the GitHub lists miss.
    """
    key = os.environ.get("USAJOBS_API_KEY")
    email = os.environ.get("USAJOBS_EMAIL")
    if not key or not email:
        logger.info("USAJOBS_API_KEY/USAJOBS_EMAIL not set — skipping USAJOBS.")
        return []

    headers = {"Host": "data.usajobs.gov", "User-Agent": email, "Authorization-Key": key}
    jobs, seen = [], set()
    for keyword, location in USAJOBS_QUERIES:
        params = {"Keyword": keyword, "ResultsPerPage": 25}
        if location:
            params["LocationName"] = location
        try:
            resp = requests.get(USAJOBS_URL, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            items = resp.json().get("SearchResult", {}).get("SearchResultItems", [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error fetching USAJOBS for '%s': %s", keyword, exc)
            continue

        added = 0
        for item in items:
            descriptor = item.get("MatchedObjectDescriptor", {})
            title = descriptor.get("PositionTitle", "")
            # Keep genuine internships / Pathways student-trainee roles.
            if not any(hint in title.lower() for hint in USAJOBS_INTERN_HINTS):
                continue
            uid = descriptor.get("PositionID") or descriptor.get("PositionURI", "")
            if not uid or uid in seen:
                continue
            seen.add(uid)
            jobs.append(_normalize_usajobs_item(descriptor))
            added += 1
        logger.info("Fetched %d USAJOBS intern posting(s) for '%s'", added, keyword)

    return jobs


def fetch_ctf_events(limit=8, weeks_ahead=3):
    """Fetch upcoming CTF competitions from CTFtime (public API, no key)."""
    now = datetime.now(timezone.utc)
    params = {
        "limit": 100,
        "start": int(now.timestamp()),
        "finish": int((now + timedelta(weeks=weeks_ahead)).timestamp()),
    }
    try:
        resp = requests.get(
            CTFTIME_URL, params=params, headers={"User-Agent": USER_AGENT}, timeout=30
        )
        resp.raise_for_status()
        events = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching CTFtime events: %s", exc)
        return []

    parsed = []
    for e in events:
        parsed.append(
            {
                "title": e.get("title", ""),
                "start": e.get("start", ""),
                "finish": e.get("finish", ""),
                "url": e.get("url") or e.get("ctftime_url", ""),
                "format": e.get("format", ""),
                "onsite": bool(e.get("onsite", False)),
                "location": e.get("location", "")
                or ("On-site" if e.get("onsite") else "Online"),
                "weight": e.get("weight", 0) or 0,
            }
        )
    parsed.sort(key=lambda x: x["start"])
    result = parsed[:limit]
    logger.info("Fetched %d upcoming CTF event(s)", len(result))
    return result


def fetch_htb_profile():
    """Fetch the recipient's HackTheBox stats (optional; needs an App Token).

    Skipped silently if HTB_TOKEN / HTB_USER_ID aren't set. Parsed defensively so
    an unexpected response shape degrades to whatever fields are present.
    """
    token = os.environ.get("HTB_TOKEN")
    user_id = os.environ.get("HTB_USER_ID")
    if not token or not user_id:
        logger.info("HTB_TOKEN/HTB_USER_ID not set — skipping HTB profile.")
        return None

    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    try:
        resp = requests.get(
            f"{HTB_API}/user/profile/basic/{user_id}", headers=headers, timeout=30
        )
        resp.raise_for_status()
        profile = resp.json().get("profile", {}) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching HTB profile: %s", exc)
        return None

    team = profile.get("team")
    result = {
        "name": profile.get("name", ""),
        "rank": profile.get("rank", ""),
        "points": profile.get("points", 0),
        "ranking": profile.get("ranking", ""),
        "user_owns": profile.get("user_owns", 0),
        "system_owns": profile.get("system_owns", 0),
        "respects": profile.get("respects", 0),
        "country": profile.get("country_name", ""),
        "team": team.get("name", "") if isinstance(team, dict) else "",
    }
    logger.info(
        "Fetched HTB profile for %s (rank %s, %s pts)",
        result["name"] or user_id,
        result["rank"] or "?",
        result["points"],
    )
    return result


def _pocs_for_cve(cve_id, session):
    """Return up to 3 public PoC repos (most-starred first) for a CVE, or []."""
    parts = cve_id.split("-")
    if len(parts) < 2 or not parts[1].isdigit():
        return []
    url = f"{POC_BASE}/{parts[1]}/{cve_id}.json"
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        repos = resp.json()
    except Exception:  # noqa: BLE001 — best-effort enrichment
        return []
    repos = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
    return [
        {
            "url": r.get("html_url", ""),
            "stars": r.get("stargazers_count", 0),
            "desc": (r.get("description") or "")[:120],
        }
        for r in repos[:3]
        if r.get("html_url")
    ]


def enrich_with_pocs(items, max_lookups=20):
    """Attach a 'pocs' list to each CVE/KEV item (best-effort, capped lookups)."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    for i, item in enumerate(items):
        cve_id = item.get("id", "")
        if i < max_lookups and cve_id.startswith("CVE-"):
            item["pocs"] = _pocs_for_cve(cve_id, session)
        else:
            item["pocs"] = []
    with_poc = sum(1 for it in items if it.get("pocs"))
    logger.info(
        "PoC enrichment: %d of %d checked item(s) have public exploits",
        with_poc,
        min(len(items), max_lookups),
    )
    return items


def load_seen_jobs(path=SEEN_JOBS_PATH):
    """Load the set of internship IDs seen on previous runs."""
    try:
        with open(path, encoding="utf-8") as f:
            return set(json.load(f))
    except (FileNotFoundError, ValueError, OSError):
        return set()


def save_seen_jobs(jobs, path=SEEN_JOBS_PATH):
    """Persist the current internship IDs for next run's new-vs-seen diff."""
    ids = sorted({_job_id(j) for j in jobs if _job_id(j)})
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ids, f, indent=0)
    except OSError as exc:
        logger.warning("Could not save job state to %s: %s", path, exc)


def _job_id(job):
    return job.get("link") or job.get("title", "")


def flag_new_jobs(jobs, seen):
    """Mark each job `is_new` if unseen. First ever run (no state) = no 'new'."""
    first_run = not seen
    new_count = 0
    for job in jobs:
        job["is_new"] = (not first_run) and (_job_id(job) not in seen)
        if job["is_new"]:
            new_count += 1
    if first_run:
        logger.info("First run — establishing internship baseline (nothing marked new)")
    else:
        logger.info("%d internship(s) are new since the last run", new_count)
    return jobs


def _merge_jobs(*job_lists, cap=50):
    """Combine job sources, dedup by ID, re-sort MA/remote-first then newest."""
    merged, seen = [], set()
    for jobs in job_lists:
        for job in jobs:
            jid = _job_id(job)
            if not jid or jid in seen:
                continue
            seen.add(jid)
            merged.append(job)
    merged.sort(key=lambda j: (j["rank"], -j.get("date_posted", 0)))
    return merged[:cap]


def fetch_all():
    """Fetch everything, returning a single dict. Never raises."""
    logger.info("Starting data fetch…")

    cves = fetch_cves()
    kev = fetch_kev()
    # Flag which CVEs/KEV entries have public exploits (KEV first — highest value).
    enrich_with_pocs(kev)
    enrich_with_pocs(cves, max_lookups=15)

    jobs = _merge_jobs(fetch_jobs(), fetch_usajobs())
    # New-since-last-run diff for internships.
    seen = load_seen_jobs()
    flag_new_jobs(jobs, seen)
    save_seen_jobs(jobs)

    data = {
        "news": fetch_rss_feeds(),
        "cves": cves,
        "kev": kev,
        "jobs": jobs,
        "ctf": fetch_ctf_events(),
        "htb": fetch_htb_profile(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(
        "Fetch complete: %d news, %d cves, %d kev, %d jobs, %d ctf, htb=%s",
        len(data["news"]),
        len(data["cves"]),
        len(data["kev"]),
        len(data["jobs"]),
        len(data["ctf"]),
        "yes" if data["htb"] else "no",
    )
    return data


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    print(json.dumps(fetch_all(), indent=2)[:5000])
