"""
briefing.py — turn fetched data into an AI-summarized, dark-themed email.

Flow:
  1. fetcher.fetch_all()  ->  raw news / CVEs / jobs
  2. GitHub Models (Llama-4-Scout) summarizes it for the recipient
  3. Render dark HTML + plain-text email and send via Gmail SMTP (SSL, 465)

Designed to be resilient: if the AI call fails we still send a plain briefing
built directly from the fetched data so the run is never silently lost.
"""

import logging
import os
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import markdown as md
from dateutil import parser as dateparser
from openai import OpenAI

import fetcher

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("briefing")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GH_MODELS_ENDPOINT = "https://models.inference.ai.azure.com"
MODEL = "Llama-4-Scout-17B-16E-Instruct"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

RECIPIENT_CONTEXT = """\
The recipient is:
- A UMass Amherst cybersecurity student.
- Actively working through the HackTheBox Web Hacking path.
- Currently on the Web Proxies module (Burp Suite, HTTP interception, request
  manipulation).
- Actively looking for penetration testing internships.
Tailor tone and relevance to this person. Explain *why* items matter to them.
"""

SYSTEM_PROMPT = """\
You are a sharp cybersecurity news editor writing a thorough daily briefing for a
specific student. Be concrete. Add a short description to every item so the reader
understands it, but DO NOT DROP ITEMS to save space — completeness matters more
than brevity here. The reader would rather scroll than miss something. No invented
facts — only summarize what you are given. Use the provided links. Write in Markdown.
"""

# The exact section layout the user asked for.
OUTPUT_INSTRUCTIONS = """\
Produce the briefing using EXACTLY these Markdown sections, in this order. Use
`##` headings with the emoji shown. Omit a section only if you truly have nothing
for it, and if so say "Nothing notable today."

Overall rule: BE COMPLETE. Include every relevant item you are given rather than a
"best of" subset, and give each a short description. Long is fine.

## 🔥 TOP STORIES
Cover ALL the notable news items, not just a few. For each: a bold headline linked
to the source, then one or two sentences on what happened and why it matters to a
security student. It's fine for this to be a long list.

## 🚨 CVEs TO KNOW
Include every CVSS 7.0+ or web-security-relevant CVE you are given. For each:
`**CVE-ID** (CVSS x.x — Severity)` linked to NVD, then a one-line plain-English
description and, where it applies, why it's relevant to web hacking. **Lead with
any CVEs from the CISA KEV list — those are confirmed actively exploited in the
wild — and mark them `🔴 Actively exploited` (note if there's known ransomware
use).** If a CVE line says a public PoC exists, add `🧪 PoC available` and keep
the PoC link — knowing what's weaponized is exactly how a pentester triages.

## 🎯 RELEVANT TO YOUR HTB PATH
Anything useful for web hacking, HTTP proxies, Burp Suite, or OWASP — tie it to
the Web Proxies module they're on. Include HackTheBox news/announcements here too.

DO NOT WRITE any of these sections — they are generated automatically from live
data and inserted for you, and writing them yourself risks dropping or garbling
entries: `## 🏆 YOUR HACKTHEBOX PROGRESS`, `## 📚 SKILL BUILDER`,
`## 🎓 UPCOMING CTFs`, `## 💼 INTERNSHIP OPPORTUNITIES`. After the HTB PATH
section, skip straight to QUICK HITS; everything above will be inserted between
them.

## 📌 QUICK HITS
Short one-line bullets for any other notable items that didn't fit above.
"""

# We build the 💼 INTERNSHIP OPPORTUNITIES section in code (not via the model) so
# that EVERY posting is guaranteed to appear — the model was silently dropping
# some. This heading must match what we splice against in assemble_briefing().
INTERNSHIP_HEADING = "## 💼 INTERNSHIP OPPORTUNITIES"
QUICK_HITS_HEADING = "## 📌 QUICK HITS"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
# The free GitHub Models tier caps llama-4-scout at 8000 *input* tokens. The
# internship list is built in code (not sent to the model), so the only sections
# here are KEV, news, and CVEs. Order is deliberate: KEV first (small, must-keep),
# news next, CVEs LAST because CVEs are the only unbounded section (a busy day
# brings hundreds). If MAX_PROMPT_CHARS has to trim, it trims the tail — CVEs
# first, then news. MAX_PROMPT_CHARS keeps the whole prompt under the token limit
# (~3.3 chars/token → ~20000 chars ≈ 6100 tokens, with headroom).
PROMPT_NEWS_CAP = 60
PROMPT_CVES_CAP = 40
MAX_PROMPT_CHARS = 20000


def _poc_note(pocs):
    """Short ' [PoC: url]' note for the prompt when a public exploit exists."""
    if not pocs:
        return ""
    top = pocs[0]
    return f" [🧪 public PoC exists: {top['url']}]"


def _format_data_for_prompt(data):
    # NOTE: internships are intentionally NOT included here — that section is
    # built deterministically in build_internships_markdown() and spliced in
    # afterward, so the model never has the chance to drop a posting.
    lines = []

    # KEV first — small, must-keep, and never trimmed.
    lines.append("=== ACTIVELY EXPLOITED (CISA KEV, recently added) ===")
    if data.get("kev"):
        for k in data["kev"]:
            ransom = (
                " [known ransomware use]"
                if str(k.get("ransomware", "")).lower() == "known"
                else ""
            )
            poc = _poc_note(k.get("pocs"))
            lines.append(
                f"- {k['id']} — {k['vendor']} {k['product']}: {k['name']}"
                f" (added {k['date_added']}){ransom}{poc} {k['link']}"
            )
            if k["description"]:
                lines.append(f"  {k['description'][:220]}")
    else:
        lines.append("(no recently added KEV entries)")

    lines.append("\n=== NEWS (RSS, last 24h) ===")
    if data["news"]:
        for item in data["news"][:PROMPT_NEWS_CAP]:
            lines.append(f"- [{item['source']}] {item['title']}")
            if item["link"]:
                lines.append(f"  link: {item['link']}")
            if item["summary"]:
                lines.append(f"  summary: {item['summary'][:220]}")
    else:
        lines.append("(no news fetched)")

    # CVEs last: the only unbounded section, so it absorbs any truncation.
    lines.append("\n=== CVEs (NVD, last 24h — sorted by CVSS, highest first) ===")
    if data["cves"]:
        for c in data["cves"][:PROMPT_CVES_CAP]:
            score = f"{c['score']:.1f}" if c["score"] else "N/A"
            poc = _poc_note(c.get("pocs"))
            lines.append(f"- {c['id']} (CVSS {score} {c['severity']}){poc} {c['link']}")
            if c["description"]:
                lines.append(f"  {c['description'][:220]}")
    else:
        lines.append("(no CVEs fetched)")

    block = "\n".join(lines)
    if len(block) > MAX_PROMPT_CHARS:
        logger.warning(
            "Prompt data %d chars — trimming trailing CVEs to %d to fit the token "
            "limit; KEV and news come first and are kept (internships are built "
            "separately in code and unaffected)",
            len(block),
            MAX_PROMPT_CHARS,
        )
        block = block[:MAX_PROMPT_CHARS] + "\n…(remaining lower-priority items omitted)"
    return block


def summarize(data):
    """Call GitHub Models to produce the Markdown briefing. Returns Markdown str."""
    token = os.environ.get("GH_MODELS_TOKEN")
    if not token:
        raise RuntimeError("GH_MODELS_TOKEN is not set")

    client = OpenAI(base_url=GH_MODELS_ENDPOINT, api_key=token)
    user_content = (
        RECIPIENT_CONTEXT
        + "\n"
        + OUTPUT_INSTRUCTIONS
        + "\n\nHere is today's fetched data:\n\n"
        + _format_data_for_prompt(data)
    )

    logger.info("Requesting summary from %s…", MODEL)
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.4,
        # Generous output budget so a complete, item-by-item briefing (every
        # internship, every notable story) isn't cut off mid-list.
        max_tokens=4000,
    )
    content = response.choices[0].message.content
    logger.info("Received %d chars of summary", len(content or ""))
    return content.strip()


def build_internships_markdown(jobs):
    """Deterministically render the 💼 section with EVERY posting and its details.

    Built in code rather than by the model so no posting can be dropped. Each
    entry includes company, all locations, term, category, degrees, and a visa
    note where relevant.
    """
    lines = [INTERNSHIP_HEADING]
    if not jobs:
        lines.append(
            "No active security internships in the tracked lists today — "
            "check again tomorrow (the next hiring cycle ramps up in the fall)."
        )
        return "\n".join(lines)

    new_count = sum(1 for j in jobs if j.get("is_new"))
    summary = f"*{len(jobs)} active security internship(s) — Massachusetts and remote first."
    if new_count:
        summary += f" **🆕 {new_count} new since yesterday (apply to these first).**"
    lines.append(summary + "*")
    lines.append("")

    # New postings first within the already MA/remote-sorted list.
    ordered = sorted(jobs, key=lambda j: not j.get("is_new"))
    for j in ordered:
        flag = "🆕 " if j.get("is_new") else ""
        title = f"**[{j['title']}]({j['link']})**" if j.get("link") else f"**{j['title']}**"
        lead = f"{flag}{title} — {j['company']}" if j.get("company") else f"{flag}{title}"
        lines.append(f"- {lead}")

        # Detail line: location · term · category · degrees.
        details = [f"📍 {j['location_str']}"]
        if j.get("term"):
            details.append(j["term"])
        if j.get("category"):
            details.append(j["category"])
        degrees = j.get("degrees") or []
        if degrees:
            details.append("/".join(degrees))
        lines.append(f"  <br>{' · '.join(details)}")

        # Visa/citizenship flag — matters a lot for internship eligibility.
        sponsorship = (j.get("sponsorship") or "").lower()
        if "citizen" in sponsorship or "does not offer" in sponsorship:
            lines.append(f"  <br>⚠️ {j['sponsorship']}")
    return "\n".join(lines)


# --- PortSwigger Web Security Academy: the go-to free labs for web pentesting ---
# Each topic maps trigger keywords (matched against today's CVEs/news) to its
# free Academy lab. Ordered roughly by how central it is to the Web Hacking path.
PORTSWIGGER_TOPICS = [
    ("SQL injection", "https://portswigger.net/web-security/sql-injection",
     ["sql injection", "sqli"]),
    ("Cross-site scripting (XSS)", "https://portswigger.net/web-security/cross-site-scripting",
     ["cross-site scripting", "xss"]),
    ("Server-side request forgery (SSRF)", "https://portswigger.net/web-security/ssrf",
     ["ssrf", "server-side request forgery"]),
    ("OS command injection", "https://portswigger.net/web-security/os-command-injection",
     ["command injection", "os command"]),
    ("Path traversal", "https://portswigger.net/web-security/file-path-traversal",
     ["path traversal", "directory traversal"]),
    ("File upload vulnerabilities", "https://portswigger.net/web-security/file-upload",
     ["file upload", "unrestricted upload", "arbitrary file"]),
    ("Access control & IDOR", "https://portswigger.net/web-security/access-control",
     ["access control", "idor", "authorization bypass", "privilege escalation"]),
    ("Authentication", "https://portswigger.net/web-security/authentication",
     ["authentication bypass", "auth bypass", "improper authentication"]),
    ("XML external entity (XXE)", "https://portswigger.net/web-security/xxe",
     ["xxe", "xml external entity"]),
    ("Insecure deserialization", "https://portswigger.net/web-security/deserialization",
     ["deserialization", "deserialisation"]),
    ("Server-side template injection", "https://portswigger.net/web-security/server-side-template-injection",
     ["template injection", "ssti"]),
    ("JWT attacks", "https://portswigger.net/web-security/jwt", ["jwt", "json web token"]),
    ("CSRF", "https://portswigger.net/web-security/csrf", ["csrf", "cross-site request forgery"]),
    ("HTTP request smuggling", "https://portswigger.net/web-security/request-smuggling",
     ["request smuggling"]),
    ("Web cache poisoning", "https://portswigger.net/web-security/web-cache-poisoning",
     ["cache poisoning", "cache deception"]),
    ("Business logic / prototype pollution", "https://portswigger.net/web-security/prototype-pollution",
     ["prototype pollution"]),
    ("GraphQL API vulnerabilities", "https://portswigger.net/web-security/graphql",
     ["graphql"]),
    ("OAuth authentication", "https://portswigger.net/web-security/oauth", ["oauth"]),
    ("CORS", "https://portswigger.net/web-security/cors", ["cors", "cross-origin"]),
    ("NoSQL injection", "https://portswigger.net/web-security/nosql-injection", ["nosql"]),
]

# Always shown — tied to the recipient's current Web Proxies / Burp Suite module.
PINNED_LEARNING = [
    ("Burp Suite: get started", "https://portswigger.net/burp/documentation/desktop/getting-started"),
    ("PortSwigger: intercepting HTTP requests with Burp Proxy",
     "https://portswigger.net/burp/documentation/desktop/tools/proxy"),
    ("All Web Security Academy topics", "https://portswigger.net/web-security/all-topics"),
]


def build_skillbuilder_markdown(data):
    """Deterministic 📚 section: PortSwigger labs matching today's web vulns, plus
    pinned Burp/Web-Proxies resources for the recipient's current HTB module."""
    haystack = " ".join(
        [c.get("description", "") for c in data.get("cves", [])]
        + [f"{k.get('name','')} {k.get('description','')}" for k in data.get("kev", [])]
        + [n.get("title", "") for n in data.get("news", [])]
    ).lower()

    matched = [
        (name, url)
        for name, url, keywords in PORTSWIGGER_TOPICS
        if any(kw in haystack for kw in keywords)
    ]

    lines = ["## 📚 SKILL BUILDER — PortSwigger Web Security Academy"]
    lines.append(
        "*Free hands-on labs. Pinned to your current Burp Suite / Web Proxies "
        "module, plus topics tied to today's vulnerabilities.*"
    )
    lines.append("")
    lines.append("**Your current module:**")
    for name, url in PINNED_LEARNING:
        lines.append(f"- [{name}]({url})")
    if matched:
        lines.append("")
        lines.append("**Relevant to today's CVEs/news:**")
        for name, url in matched:
            lines.append(f"- [{name}]({url})")
    return "\n".join(lines)


def build_ctf_markdown(events):
    """Deterministic 🎓 section: upcoming CTF competitions from CTFtime."""
    lines = ["## 🎓 UPCOMING CTFs"]
    if not events:
        lines.append("No upcoming events found (or CTFtime was unreachable).")
        return "\n".join(lines)
    lines.append("*Great practice and résumé fodder for security roles.*")
    lines.append("")
    now = datetime.now(timezone.utc)
    for e in events:
        when, rel = e["start"][:10], ""
        try:
            start = dateparser.parse(e["start"])
            days = (start - now).days
            rel = " (today)" if days == 0 else f" (in {days}d)" if days > 0 else ""
            when = start.strftime("%a %b %d")
        except (ValueError, TypeError):
            pass
        place = "🌐 Online" if not e.get("onsite") else f"📍 {e.get('location', 'On-site')}"
        fmt = f" · {e['format']}" if e.get("format") else ""
        title = f"**[{e['title']}]({e['url']})**" if e.get("url") else f"**{e['title']}**"
        lines.append(f"- {title} — {when}{rel} · {place}{fmt}")
    return "\n".join(lines)


def build_htb_markdown(htb):
    """Deterministic 🏆 section: the recipient's HackTheBox stats (if available)."""
    if not htb:
        return ""
    lines = ["## 🏆 YOUR HACKTHEBOX PROGRESS"]
    name = htb.get("name") or "You"
    rank = htb.get("rank") or "—"
    lines.append(f"**{name}** · Rank: **{rank}**")
    stats = []
    if htb.get("points"):
        stats.append(f"{htb['points']} pts")
    if htb.get("ranking"):
        stats.append(f"global #{htb['ranking']}")
    if htb.get("user_owns"):
        stats.append(f"{htb['user_owns']} user owns")
    if htb.get("system_owns"):
        stats.append(f"{htb['system_owns']} system owns")
    if htb.get("respects"):
        stats.append(f"{htb['respects']} respects")
    if stats:
        lines.append(f"  <br>{' · '.join(stats)}")
    lines.append(
        "  <br>*Keep the streak going — one Web Proxies lab a day compounds fast.*"
    )
    return "\n".join(lines)


def assemble_briefing(ai_markdown, data):
    """Splice all code-built sections into the model's briefing.

    The model writes only the narrative sections (Top Stories, CVEs, HTB Path,
    Quick Hits). Everything that must be complete/accurate — HTB progress, skill
    labs, CTFs, and the full internship list — is built here and inserted just
    before QUICK HITS, so the model can never drop or garble it.
    """
    md = ai_markdown

    # Defensive: strip any of our sections the model wrote anyway (avoid dupes).
    for heading in (INTERNSHIP_HEADING, "## 🏆", "## 📚", "## 🎓"):
        while heading in md:
            start = md.index(heading)
            after = md.find("\n## ", start + 1)
            md = md[:start] + (md[after + 1 :] if after != -1 else "")

    # Order: personal progress, then learning, then opportunities.
    sections = [
        build_htb_markdown(data.get("htb")),
        build_skillbuilder_markdown(data),
        build_ctf_markdown(data.get("ctf", [])),
        build_internships_markdown(data["jobs"]),
    ]
    block = "\n\n".join(s for s in sections if s)

    if QUICK_HITS_HEADING in md:
        idx = md.index(QUICK_HITS_HEADING)
        return md[:idx].rstrip() + "\n\n" + block + "\n\n" + md[idx:]
    return md.rstrip() + "\n\n" + block + "\n"


def fallback_markdown(data):
    """Build a plain briefing from raw data when the AI call fails."""
    lines = ["## ⚠️ AI summarization unavailable", "", "Raw fetched data below.", ""]

    lines.append("## 🔥 TOP STORIES")
    for item in data["news"][:15]:
        lines.append(f"- **[{item['title']}]({item['link']})** — {item['source']}")
    if not data["news"]:
        lines.append("Nothing fetched today.")

    lines.append("\n## 🚨 CVEs TO KNOW")
    for k in data.get("kev", []):
        poc = " · 🧪 PoC" if k.get("pocs") else ""
        lines.append(
            f"- 🔴 **[{k['id']}]({k['link']})** actively exploited — "
            f"{k['vendor']} {k['product']}: {k['name']}{poc}"
        )
    for c in data["cves"][:20]:
        score = f"{c['score']:.1f}" if c["score"] else "N/A"
        poc = " · 🧪 PoC" if c.get("pocs") else ""
        lines.append(
            f"- **[{c['id']}]({c['link']})** (CVSS {score} {c['severity']}){poc}"
        )
    if not data["cves"] and not data.get("kev"):
        lines.append("Nothing fetched today.")

    # Reuse the same deterministic builders so the fallback is just as complete.
    for section in (
        build_htb_markdown(data.get("htb")),
        build_skillbuilder_markdown(data),
        build_ctf_markdown(data.get("ctf", [])),
        build_internships_markdown(data["jobs"]),
    ):
        if section:
            lines.append("")
            lines.append(section)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Email rendering
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """\
<!-- dark themed briefing -->
<div style="margin:0;padding:0;background-color:#0d1117;">
  <div style="max-width:680px;margin:0 auto;padding:24px 20px;
              font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
              color:#c9d1d9;background-color:#0d1117;">
    <div style="border-bottom:1px solid #21262d;padding-bottom:16px;margin-bottom:8px;">
      <div style="font-size:20px;font-weight:bold;color:#58a6ff;letter-spacing:0.5px;">
        &#128272; CYBER BRIEFING
      </div>
      <div style="font-size:13px;color:#8b949e;margin-top:4px;">{date_str}</div>
    </div>
    <div class="briefing-body" style="font-size:14px;line-height:1.6;">
      {body}
    </div>
    <div style="border-top:1px solid #21262d;margin-top:28px;padding-top:14px;
                font-size:11px;color:#6e7681;">
      Auto-generated by your Morning Briefing bot · GitHub Actions + GitHub Models
      · {news} news / {cves} CVEs / {kev} KEV / {jobs} internships / {ctf} CTFs
    </div>
  </div>
</div>
"""

# Inline-ish styling for the AI's Markdown-converted HTML. Gmail honors a <style>
# block in the head; we also lean on the container color above for fallbacks.
EMAIL_STYLES = """\
<style>
  .briefing-body h2 {
    color:#58a6ff; font-size:16px; margin:26px 0 10px 0;
    padding-bottom:6px; border-bottom:1px solid #21262d;
  }
  .briefing-body a { color:#79c0ff; text-decoration:none; }
  .briefing-body a:hover { text-decoration:underline; }
  .briefing-body strong { color:#e6edf3; }
  .briefing-body code {
    background:#161b22; color:#ff7b72; padding:1px 5px;
    border-radius:4px; font-size:13px;
  }
  .briefing-body ul { padding-left:20px; margin:8px 0; }
  .briefing-body li { margin:6px 0; }
  .briefing-body p { margin:8px 0; }
</style>
"""


def render_html(markdown_text, data, date_str):
    body_html = md.markdown(markdown_text, extensions=["extra", "sane_lists"])
    inner = HTML_TEMPLATE.format(
        date_str=date_str,
        body=body_html,
        news=len(data["news"]),
        cves=len(data["cves"]),
        kev=len(data.get("kev", [])),
        jobs=len(data["jobs"]),
        ctf=len(data.get("ctf", [])),
    )
    return EMAIL_STYLES + inner


def render_plain_text(markdown_text, date_str):
    header = f"CYBER BRIEFING — {date_str}\n{'=' * 40}\n\n"
    return header + markdown_text


# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------
def send_email(subject, html_body, text_body):
    sender = os.environ.get("EMAIL_SENDER")
    recipient = os.environ.get("EMAIL_RECIPIENT")
    password = os.environ.get("EMAIL_PASSWORD")

    missing = [
        name
        for name, val in (
            ("EMAIL_SENDER", sender),
            ("EMAIL_RECIPIENT", recipient),
            ("EMAIL_PASSWORD", password),
        )
        if not val
    ]
    if missing:
        raise RuntimeError(f"Missing email env var(s): {', '.join(missing)}")

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    # Order matters: last part is the preferred one (HTML).
    message.attach(MIMEText(text_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    logger.info("Sending email to %s…", recipient)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
        server.login(sender, password)
        server.sendmail(sender, recipient, message.as_string())
    logger.info("Email sent.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    data = fetcher.fetch_all()

    try:
        ai_markdown = summarize(data)
        # Internship section is built in code and spliced in — guarantees every
        # posting appears regardless of what the model chose to include.
        markdown_text = assemble_briefing(ai_markdown, data)
    except Exception as exc:  # noqa: BLE001 — still send *something* useful
        logger.error("AI summarization failed (%s); using fallback briefing.", exc)
        markdown_text = fallback_markdown(data)

    now = datetime.now()
    date_str = now.strftime("%A, %B %d, %Y")
    subject = f"🔐 Cyber Briefing — {date_str}"

    html_body = render_html(markdown_text, data, date_str)
    text_body = render_plain_text(markdown_text, date_str)

    send_email(subject, html_body, text_body)
    logger.info("Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        logger.critical("Briefing run failed: %s", exc)
        sys.exit(1)
