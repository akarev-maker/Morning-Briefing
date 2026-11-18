"""
curate.py: turn the raw list of stories into ranked, de-duplicated ones.

Several outlets usually cover the same big story. This groups those articles
into one story, counts how many different outlets covered it ("coverage"), and
ranks by that count. Coverage is a decent signal of importance that needs no
model, which is why it is also the ranking used when Gemini is down.

It also finds CVE IDs mentioned in the stories and checks each one against
CISA KEV (exploited in the wild) and PoC-in-GitHub (public exploit code).
"""

import logging
import math
import re
from collections import Counter

import fetcher

logger = logging.getLogger("briefing.curate")

# Two articles count as the same story when their TF-IDF cosine similarity is at
# least this. Tuned on real data (2026-11-17, 50 stories): true duplicates
# scored 0.26 to 0.87, the closest unrelated pair scored 0.22. Raise it and real
# duplicates show up as separate stories; lower it and unrelated stories merge.
SIMILARITY_THRESHOLD = 0.25

# Upper bound on PoC-in-GitHub requests per run (one HTTP request each).
MAX_POC_LOOKUPS = 20

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Keeps "6.2", "java4shell" and "third-party" as single words.
_WORD_RE = re.compile(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*")

STOPWORDS = frozenset(
    """
    a an the and or of to in on for with by from at as is are was were be been
    how why what who when where which while new after amid its it this that these
    those their your you we our us they them over into than then about up out not
    now via can will has have had more most also just like only some such other
    many much very one two all any each both do does did says say said today
    """.split()
)


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------
def _words(text):
    return [w for w in _WORD_RE.findall(text.lower()) if w not in STOPWORDS and len(w) > 2]


def _tfidf_vectors(stories):
    """One TF-IDF vector per story, as {word: weight}, scaled to length 1.

    TF (term frequency): how often a word appears in this story. The title is
    counted twice because headlines carry the key nouns.
    IDF (inverse document frequency): log((1 + N) / (1 + df)) + 1, where df is
    the number of today's stories that use the word. Rare words such as
    "optimizely" weigh a lot; words in every story, such as "attack", barely
    count. Same formula as scikit-learn's TfidfVectorizer default.
    """
    docs = [_words(s["title"]) * 2 + _words(s.get("summary", "")) for s in stories]
    n = len(docs)
    df = Counter(word for doc in docs for word in set(doc))

    vectors = []
    for doc in docs:
        weights = {
            word: count * (math.log((1 + n) / (1 + df[word])) + 1)
            for word, count in Counter(doc).items()
        }
        norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
        vectors.append({word: w / norm for word, w in weights.items()})
    return vectors


def _cosine(a, b):
    """Cosine similarity of two unit-length sparse vectors: their dot product."""
    if len(a) > len(b):
        a, b = b, a
    return sum(weight * b.get(word, 0.0) for word, weight in a.items())


def _cves_in(story):
    text = f"{story['title']} {story.get('summary', '')}"
    return {m.upper() for m in CVE_RE.findall(text)}


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------
def _find(parent, i):
    while parent[i] != i:
        parent[i] = parent[parent[i]]  # path halving keeps the trees shallow
        i = parent[i]
    return i


def cluster(stories, threshold=SIMILARITY_THRESHOLD):
    """Group articles about the same story. Returns a list of lists of stories.

    Two articles are linked if they have the same ID (same URL), mention the
    same CVE, or are similar enough. Groups are the connected sets of links
    (union-find), so if A matches B and B matches C, all three are one story.
    """
    n = len(stories)
    parent = list(range(n))
    vectors = _tfidf_vectors(stories)
    cves = [_cves_in(s) for s in stories]

    for i in range(n):
        for j in range(i + 1, n):
            same = (
                stories[i]["id"] == stories[j]["id"]
                or cves[i] & cves[j]
                or _cosine(vectors[i], vectors[j]) >= threshold
            )
            if same:
                parent[_find(parent, i)] = _find(parent, j)

    groups = {}
    for i in range(n):
        groups.setdefault(_find(parent, i), []).append(stories[i])
    return list(groups.values())


def _merge(group):
    """Collapse one group of articles into a single story."""
    # The earliest article is usually the original report. Undated ones go last.
    members = sorted(group, key=lambda s: s.get("published") or "9999")
    lead = members[0]

    sources = list(dict.fromkeys(s["source"] for s in members))
    categories = Counter(s["category"] for s in members)
    # Majority category; on a tie, cyber wins (same rule as classify_title).
    category = max(("cyber", "ai"), key=lambda c: (categories[c], c == "cyber"))

    hn = [s for s in members if s.get("points")]
    top_hn = max(hn, key=lambda s: s["points"]) if hn else None

    cves = set()
    for s in members:
        cves |= _cves_in(s)

    return {
        "id": lead["id"],
        "category": category,
        "title": lead["title"],
        "link": lead["link"],
        # HN items have no summary, so take the longest one in the group.
        "summary": max((s.get("summary", "") for s in members), key=len),
        "published": lead.get("published", ""),
        "sources": sources,
        "coverage": len(sources),
        "points": top_hn["points"] if top_hn else None,
        "comments": top_hn.get("comments", "") if top_hn else "",
        "links": sorted({s["link"] for s in members if s["link"]}),
        "cves": sorted(cves),
    }


def rank(stories):
    """Most-covered first, then most HN points, then newest."""
    return sorted(
        stories,
        key=lambda s: (s["coverage"], s["points"] or 0, s["published"] or ""),
        reverse=True,
    )


# ---------------------------------------------------------------------------
# CVE checks
# ---------------------------------------------------------------------------
def tag_cves(stories, kev, pocs_lookup=fetcher.pocs_for_cve, max_lookups=MAX_POC_LOOKUPS):
    """Attach `cve_info` to each story: KEV status and public exploits per CVE.

    `stories` should already be ranked, so if the lookup cap is hit it is the
    least important stories that go without PoC checks.
    """
    cache, lookups = {}, 0
    for story in stories:
        info = []
        for cve_id in story["cves"]:
            if cve_id not in cache and lookups < max_lookups:
                cache[cve_id] = pocs_lookup(cve_id)
                lookups += 1
            entry = kev.get(cve_id)
            info.append(
                {
                    "id": cve_id,
                    "kev": entry is not None,
                    "ransomware": bool(entry) and entry.get("ransomware") == "Known",
                    "pocs": cache.get(cve_id, []),
                }
            )
        story["cve_info"] = info
        story["exploited"] = any(c["kev"] for c in info)
        story["has_poc"] = any(c["pocs"] for c in info)
    mentioned = {c for s in stories for c in s["cves"]}
    logger.info(
        "CVE checks: %d CVE(s) mentioned, %d in KEV, %d PoC lookup(s)",
        len(mentioned),
        sum(1 for c in mentioned if c in kev),
        lookups,
    )
    return stories


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def curate(news, kev):
    """Raw articles in, ranked de-duplicated stories (with CVE tags) out."""
    groups = cluster(news)
    stories = rank([_merge(g) for g in groups])
    tag_cves(stories, kev)
    merged = sum(1 for g in groups if len(g) > 1)
    logger.info(
        "Curated %d article(s) into %d stor%s (%d covered by more than one article)",
        len(news), len(stories), "y" if len(stories) == 1 else "ies", merged,
    )
    return stories


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    for story in curate(fetcher.fetch_rss_feeds() + fetcher.fetch_hn(), fetcher.fetch_kev()):
        tags = [t for t, on in (("KEV", story["exploited"]), ("PoC", story["has_poc"])) if on]
        print(f"{story['coverage']}  {story['category']:5}  {story['title'][:70]}  {' '.join(tags)}")
        if story["coverage"] > 1:
            print(f"       covered by: {', '.join(story['sources'])}")
