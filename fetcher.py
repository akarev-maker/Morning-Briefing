"""
fetcher.py — all data fetching for the morning cybersecurity briefing.

Every fetch is wrapped so that a single broken source (a dead RSS feed, an NVD
hiccup, Indeed rate-limiting) logs a warning and returns whatever it can instead
of crashing the whole run.
"""

import json
import logging
import os
import re
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

# HackTheBox Academy API (needs a personal App Token — optional; skipped if
# unset). The recipient studies via Academy, so we track module/path progress
# rather than the labs/machines platform.
HTB_ACADEMY_API = "https://academy.hackthebox.com/api/v2"

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


def _strip_html(text, limit=None):
    """Strip HTML tags and squash whitespace from untrusted free text.

    Security: feed items, CVE/KEV text, job titles, and (user-submitted) CTF event
    names all flow into a Markdown->HTML email. Removing tags at the source stops
    a hostile entry from injecting markup (e.g. `<img onerror=...>`) into the email.
    """
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", str(text))
    text = re.sub(r"\s+", " ", text).strip()
    if limit and len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def _clean_summary(text, limit=400):
    """Backwards-compatible alias — strip tags with a length cap."""
    return _strip_html(text, limit=limit)


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
                        "title": _strip_html(entry.get("title", "(untitled)")),
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
                "description": _strip_html(_english_description(cve)),
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
                "name": _strip_html(vuln.get("vulnerabilityName", "")),
                "vendor": _strip_html(vuln.get("vendorProject", "")),
                "product": _strip_html(vuln.get("product", "")),
                "description": _strip_html(vuln.get("shortDescription", "")),
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
                    "title": _strip_html(title),
                    "company": _strip_html(item.get("company_name") or ""),
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
        "title": _strip_html(descriptor.get("PositionTitle", "")),
        "company": _strip_html(descriptor.get("OrganizationName") or ""),
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


def _usajobs_is_intern(descriptor):
    """True if a USAJOBS posting is an internship / Pathways student-trainee role."""
    title = descriptor.get("PositionTitle", "").lower()
    if any(hint in title for hint in USAJOBS_INTERN_HINTS):
        return True
    details = (descriptor.get("UserArea", {}) or {}).get("Details", {}) or {}
    paths = [str(p).lower() for p in (details.get("HiringPath") or [])]
    return any(p in ("student", "internship", "intern") for p in paths)


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
            # Keep genuine internships / Pathways student-trainee roles, judged by
            # title OR the structured HiringPath field (more reliable than title).
            if not _usajobs_is_intern(descriptor):
                continue
            uid = descriptor.get("PositionID") or descriptor.get("PositionURI", "")
            if not uid or uid in seen:
                continue
            seen.add(uid)
            jobs.append(_normalize_usajobs_item(descriptor))
            added += 1
        # Log raw vs. matched so we can tell "API returned nothing" (seasonal)
        # apart from "our intern filter dropped everything".
        logger.info(
            "USAJOBS '%s': %d posting(s) returned, %d matched intern/trainee filter",
            keyword,
            len(items),
            added,
        )

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
                "title": _strip_html(e.get("title", "")),
                "start": e.get("start", ""),
                "finish": e.get("finish", ""),
                "url": e.get("url") or e.get("ctftime_url", ""),
                "format": _strip_html(e.get("format", "")),
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


def _first(d, *keys, default=None):
    """Return the first present, non-None value among keys in dict d."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return default


def _log_shape(label, status, payload):
    """Log a response's structure (keys only, not values) for schema discovery.

    Values could be personal (module names, etc.) and Actions logs are public, so
    we log only keys/lengths — enough to build the parser without leaking data.
    """
    shape = ""
    if isinstance(payload, dict):
        shape = " keys=" + ",".join(sorted(payload.keys())[:15])
        # Peek one level into a 'data'/'info' wrapper if present.
        inner = payload.get("data") if isinstance(payload.get("data"), (dict, list)) else None
        if isinstance(inner, dict):
            shape += " data.keys=" + ",".join(sorted(inner.keys())[:15])
        elif isinstance(inner, list):
            shape += f" data=list[{len(inner)}]"
            if inner and isinstance(inner[0], dict):
                shape += " item.keys=" + ",".join(sorted(inner[0].keys())[:15])
    elif isinstance(payload, list):
        shape = f" list[{len(payload)}]"
        if payload and isinstance(payload[0], dict):
            shape += " item.keys=" + ",".join(sorted(payload[0].keys())[:15])
    logger.info("HTB Academy %s -> %s%s", label, status, shape)


def _jwt_from_json(text):
    """Find a 3-segment JWT inside a JSON string (searches nested dicts)."""
    text = text.strip()
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    found = []

    def _scan(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str):
                    found.append((k.lower(), v))
                else:
                    _scan(v)
        elif isinstance(node, list):
            for v in node:
                _scan(v)

    _scan(obj)
    # Prefer token-named keys holding a real (3-segment) JWT, else any JWT value.
    named = ("token", "access_token", "accesstoken", "id_token", "jwt", "authtoken")
    for want in named:
        for key, val in found:
            if key == want and val.startswith("eyJ") and val.count(".") >= 2:
                return val
    for _key, val in found:
        if val.startswith("eyJ") and val.count(".") >= 2:
            return val
    return None


def _normalize_htb_token(raw):
    """Clean a pasted HTB token into a bare JWT.

    Handles: a leading 'Bearer '/quotes, a plain JSON blob, and — the common
    localStorage case — a base64-encoded JSON blob that itself starts with 'eyJ'
    (so it looks like a JWT but has only one segment).
    """
    token = (raw or "").strip().strip('"').strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    # Plain JSON blob: {"token":"eyJ...."}
    extracted = _jwt_from_json(token)
    if extracted:
        return extracted

    # Single-segment "eyJ..." with no dots -> likely base64(JSON); decode & dig.
    # Try both standard and URL-safe base64 (localStorage blobs use either).
    if token.startswith("eyJ") and "." not in token:
        import base64

        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(padded).decode("utf-8", "ignore")
                extracted = _jwt_from_json(decoded)
                if extracted:
                    return extracted
            except Exception:  # noqa: BLE001
                continue

    return token


def fetch_htb_academy():
    """Fetch the recipient's HackTheBox *Academy* progress (optional; App Token).

    Skipped silently if HTB_TOKEN isn't set. Parsed defensively across a few
    candidate field names; structure (not values) is logged so we can refine the
    parser from a live run without leaking personal data into public logs.
    """
    token = _normalize_htb_token(os.environ.get("HTB_TOKEN"))
    if not token:
        logger.info("HTB_TOKEN not set — skipping HTB Academy.")
        return None

    # Safe diagnostics (no token value): does it look like a JWT?
    segments = token.count(".") + 1
    logger.info(
        "HTB_TOKEN present: prefix=%s, jwt_segments=%d (a valid Academy JWT starts "
        "'eyJ' with 3 segments)",
        token[:3],
        segments,
    )

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            # Academy's API expects browser-like origin/referer on XHR calls.
            "Origin": "https://academy.hackthebox.com",
            "Referer": "https://academy.hackthebox.com/dashboard",
            "X-Requested-With": "XMLHttpRequest",
        }
    )

    def _get(path):
        try:
            resp = session.get(
                f"{HTB_ACADEMY_API}/{path}", timeout=30, allow_redirects=False
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("HTB Academy %s error: %s", path, exc)
            return None
        if resp.status_code != 200:
            logger.info("HTB Academy %s -> %s (not authenticated?)", path, resp.status_code)
            return None
        try:
            payload = resp.json()
        except ValueError:
            logger.info("HTB Academy %s -> 200 but non-JSON", path)
            return None
        _log_shape(path, resp.status_code, payload)
        return payload

    profile = _get("user/settings/profile")
    modules = _get("modules/completed")
    paths = _get("paths/enrolled")

    if profile is None and modules is None and paths is None:
        logger.warning(
            "HTB Academy: no data returned — the App Token may not authenticate "
            "to Academy. See README for the Academy-specific token step."
        )
        return None

    # Defensive extraction (refined once the discovery logs reveal exact keys).
    prof = profile.get("data", profile) if isinstance(profile, dict) else {}
    mod_list = modules.get("data", modules) if isinstance(modules, dict) else modules
    path_list = paths.get("data", paths) if isinstance(paths, dict) else paths

    enrolled = []
    for p in path_list or []:
        if not isinstance(p, dict):
            continue
        enrolled.append(
            {
                "name": _strip_html(str(_first(p, "name", "title", default=""))),
                "progress": _first(p, "progress", "completion_percentage", "percentage", default=None),
            }
        )

    result = {
        "name": _strip_html(str(_first(prof, "name", "username", default=""))),
        "rank": _strip_html(str(_first(prof, "rank", "rank_name", "tier", default=""))),
        "cubes": _first(prof, "cubes", "points", default=None),
        "modules_completed": len(mod_list) if isinstance(mod_list, list) else _first(prof, "modules_completed", default=None),
        "paths": enrolled,
    }
    logger.info(
        "Fetched HTB Academy progress (%s modules, %s enrolled path(s))",
        result["modules_completed"] if result["modules_completed"] is not None else "?",
        len(enrolled),
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
        "htb": fetch_htb_academy(),
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
