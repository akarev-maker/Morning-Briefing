"""Tests for clustering, coverage ranking, and CVE tagging. No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import curate  # noqa: E402
import fetcher  # noqa: E402


def _story(title, source, summary="", link=None, category="cyber", points=None,
           published="2026-11-17T12:00:00+00:00"):
    link = link or f"https://{source.replace(' ', '').lower()}.example/{abs(hash(title))}"
    return {
        "id": fetcher.story_id(link, title),
        "source": source,
        "category": category,
        "title": title,
        "link": link,
        "summary": summary,
        "published": published,
        "points": points,
        "comments": "",
    }


# Filler so IDF behaves like a real day (a handful of stories is too few for
# "rare word" to mean anything).
_FILLER = [
    _story("Uber notifies drivers of data breach affecting 150,000", "Bleeping Computer"),
    _story("Tor releases emergency update amid ongoing DDoS attack", "Bleeping Computer"),
    _story("Flipper Devices launches Linux-based multi-tool", "Bleeping Computer"),
    _story("Microsoft testing Remote Lock for lost Windows devices", "Bleeping Computer"),
    _story("Ransomware affiliate suspect extradited to US", "The Hacker News"),
    _story("Introducing ChatGPT for Sales", "OpenAI", category="ai"),
    _story("Quoting Go Proverbs", "Simon Willison", category="ai"),
    _story("Phishing kits built to steal Microsoft 365 sessions", "Dark Reading"),
]


def _titles(groups):
    return sorted(sorted(s["title"] for s in g) for g in groups)


def test_same_cve_from_three_outlets_is_one_story():
    stories = _FILLER + [
        _story("Oracle patches critical OpenJDK flaw (CVE-2026-114938)", "The Hacker News"),
        _story("Critical Java bug lets attackers run code", "Bleeping Computer",
               summary="Tracked as CVE-2026-114938, the flaw affects OpenJDK."),
        _story("Patch now: CVE-2026-114938", "Dark Reading"),
    ]
    top = curate.rank([curate._merge(g) for g in curate.cluster(stories)])[0]
    assert top["coverage"] == 3
    assert top["cves"] == ["CVE-2026-114938"]
    assert set(top["sources"]) == {"The Hacker News", "Bleeping Computer", "Dark Reading"}


def test_similar_headlines_without_cve_merge():
    stories = _FILLER + [
        _story("Hijacked Optimizely scripts served card skimmer to CNN and BBC", "The Hacker News"),
        _story("Optimizely hack infected CNN, Fox News, BBC sites with malware", "Bleeping Computer"),
    ]
    groups = curate.cluster(stories)
    optimizely = [g for g in groups if "Optimizely" in g[0]["title"]]
    assert len(optimizely) == 1 and len(optimizely[0]) == 2


def test_unrelated_stories_stay_separate():
    groups = curate.cluster(_FILLER)
    assert len(groups) == len(_FILLER)


def test_same_url_merges_even_with_different_titles():
    url = "https://calif.io/java4shell/"
    stories = _FILLER + [
        _story("Java4Shell: RCE in OpenJDK when processing Base64", "Hacker News", link=url),
        _story("Something else entirely", "Simon Willison", link=url + "?utm_source=rss"),
    ]
    groups = curate.cluster(stories)
    assert any(len(g) == 2 for g in groups)


def test_merge_is_transitive():
    # A and C share no CVE, but each shares one with B, so all three are one story.
    stories = _FILLER + [
        _story("Bug one CVE-2026-0001", "The Hacker News"),
        _story("Bugs CVE-2026-0001 and CVE-2026-0002", "Bleeping Computer"),
        _story("Bug two CVE-2026-0002", "Dark Reading"),
    ]
    groups = curate.cluster(stories)
    assert max(len(g) for g in groups) == 3


def test_coverage_counts_outlets_not_articles():
    # Two HN submissions of one story is still one outlet.
    group = [
        _story("Optimizely compromised", "Hacker News", points=668),
        _story("Optimizely skimmer on CNN", "Hacker News", points=190),
        _story("Optimizely hack", "Bleeping Computer",
               summary="A longer summary from the actual article."),
    ]
    merged = curate._merge(group)
    assert merged["coverage"] == 2
    assert merged["points"] == 668  # best HN score in the group
    assert merged["summary"] == "A longer summary from the actual article."


def test_rank_by_coverage_then_points():
    a = {"coverage": 1, "points": 900, "published": ""}
    b = {"coverage": 3, "points": None, "published": ""}
    c = {"coverage": 1, "points": 100, "published": ""}
    assert curate.rank([a, b, c]) == [b, a, c]


def test_tag_cves_marks_kev_and_poc():
    stories = [{"cves": ["CVE-2026-1"]}, {"cves": ["CVE-2026-2"]}, {"cves": []}]
    kev = {"CVE-2026-1": {"ransomware": "Known"}}
    pocs = {"CVE-2026-2": [{"url": "https://github.com/x/poc", "stars": 5}]}
    curate.tag_cves(stories, kev, pocs_lookup=lambda c: pocs.get(c, []))

    assert stories[0]["exploited"] and not stories[0]["has_poc"]
    assert stories[0]["cve_info"][0]["ransomware"]
    assert stories[1]["has_poc"] and not stories[1]["exploited"]
    assert stories[2]["cve_info"] == [] and not stories[2]["exploited"]


def test_tag_cves_respects_lookup_cap_and_caches():
    calls = []
    stories = [{"cves": ["CVE-2026-1", "CVE-2026-2"]}, {"cves": ["CVE-2026-1", "CVE-2026-3"]}]
    curate.tag_cves(stories, {}, pocs_lookup=lambda c: calls.append(c) or [], max_lookups=2)
    assert calls == ["CVE-2026-1", "CVE-2026-2"]  # repeat is cached, third is over the cap
