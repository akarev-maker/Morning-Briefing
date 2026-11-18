"""
state.py: remember what has already been emailed, so nothing repeats.

`state/sent.json` maps a key to the date it was sent:

    {"story:3f9a1c0b2e": "2026-11-17", "cve:CVE-2026-114938": "2026-11-17", ...}

Keys are prefixed by type so news and hackathons can share one file. Entries
older than KEEP_DAYS are dropped on save, which keeps the file small; nothing
is fetched from that far back anyway.

The workflow commits this file back to the repo after each run. That is the
only state the project keeps between runs.
"""

import json
import logging
import os
from datetime import date, timedelta

import fetcher

logger = logging.getLogger("briefing.state")

SENT_PATH = os.path.join("state", "sent.json")
KEEP_DAYS = 14


def load_sent(path=SENT_PATH):
    """The sent log as {key: "YYYY-MM-DD"}. Missing or unreadable means {}.

    A corrupt file must not stop the email, so the worst case is that one
    day's stories get repeated.
    """
    try:
        with open(path, encoding="utf-8") as f:
            sent = json.load(f)
    except FileNotFoundError:
        logger.info("No sent log at %s yet; starting fresh.", path)
        return {}
    except (ValueError, OSError) as exc:
        logger.warning("Could not read sent log %s (%s); starting fresh.", path, exc)
        return {}
    if not isinstance(sent, dict):
        logger.warning("Sent log %s is not a JSON object; starting fresh.", path)
        return {}
    return {str(k): str(v) for k, v in sent.items()}


def prune(sent, today=None, keep_days=KEEP_DAYS):
    """Drop entries older than `keep_days`. Unparseable dates are dropped too."""
    cutoff = ((today or date.today()) - timedelta(days=keep_days)).isoformat()
    # ISO dates (YYYY-MM-DD) sort the same as strings and as dates.
    return {k: v for k, v in sent.items() if len(v) == 10 and v >= cutoff}


def save_sent(sent, path=SENT_PATH, today=None):
    """Prune, then write the log. Writes to a temp file and renames it, so a
    crash mid-write can't leave a half-written file behind."""
    sent = prune(sent, today)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sent, f, indent=1, sort_keys=True)  # sorted = small git diffs
        f.write("\n")
    os.replace(tmp, path)
    logger.info("Saved %d sent key(s) to %s", len(sent), path)
    return sent


def mark_sent(sent, keys, today=None):
    """Record `keys` as sent today. Modifies and returns `sent`."""
    day = (today or date.today()).isoformat()
    for key in keys:
        sent[key] = day
    return sent


# ---------------------------------------------------------------------------
# News stories
# ---------------------------------------------------------------------------
def _link_keys(story):
    """One key per article in the story (its links), plus the story's own ID."""
    keys = {f"story:{fetcher.story_id(link)}" for link in story.get("links") or [story["link"]]}
    keys.add(f"story:{story['id']}")
    return keys


def story_keys(story):
    """Every key that identifies a curated story: one per article link, one
    per CVE, plus a KEV key for each CVE that was already exploited when sent.

    Links catch the same article coming back (an HN post of an article we sent
    yesterday). CVEs catch a new article about the same bug.
    """
    keys = _link_keys(story)
    for cve in story.get("cve_info", []):
        keys.add(f"cve:{cve['id']}")
        if cve["kev"]:
            keys.add(f"kev:{cve['id']}")
    return keys


def is_sent(story, sent):
    """True if this story, or the bug it is about, already went out.

    One exception: a CVE that was sent before it was exploited comes back when
    it lands in CISA KEV. "Now exploited in the wild" is new information.
    """
    if _link_keys(story) & sent.keys():
        return True

    cves = story.get("cve_info", [])
    if not cves or not all(f"cve:{c['id']}" in sent for c in cves):
        return False
    newly_exploited = any(c["kev"] and f"kev:{c['id']}" not in sent for c in cves)
    return not newly_exploited


def filter_unsent(stories, sent):
    """Stories that haven't been emailed yet, in their original order."""
    fresh = [s for s in stories if not is_sent(s, sent)]
    skipped = len(stories) - len(fresh)
    if skipped:
        logger.info("Skipped %d stor%s already sent", skipped, "y" if skipped == 1 else "ies")
    return fresh
