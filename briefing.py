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
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import markdown as md
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
You are a sharp cybersecurity news editor writing a concise, high-signal daily
briefing for a specific student. Be concrete and skimmable. No fluff, no filler,
no invented facts — only summarize what you are given. Use the provided links.
Write in Markdown.
"""

# The exact section layout the user asked for.
OUTPUT_INSTRUCTIONS = """\
Produce the briefing using EXACTLY these Markdown sections, in this order. Use
`##` headings with the emoji shown. Omit a section only if you truly have nothing
for it, and if so say "Nothing notable today."

## 🔥 TOP STORIES
The most important news. For each: a bold headline linked to the source, then one
or two sentences on what happened and why it matters to a security student.

## 🚨 CVEs TO KNOW
Only CVSS 7.0+ or web-security-relevant CVEs. For each: `**CVE-ID** (CVSS x.x —
Severity)` linked to NVD, then a one-line plain-English description and, where it
applies, why it's relevant to web hacking.

## 🎯 RELEVANT TO YOUR HTB PATH
Anything useful for web hacking, HTTP proxies, Burp Suite, or OWASP — tie it to
the Web Proxies module they're on. Include HackTheBox news/announcements here too.

## 💼 INTERNSHIP OPPORTUNITIES
A bullet list of the internship postings, each linked. Note location/remote. If
there are none, say so and suggest checking again tomorrow.

## 📌 QUICK HITS
Short one-line bullets for other notable items that didn't fit above.
"""


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
def _format_data_for_prompt(data):
    lines = []

    lines.append("=== NEWS (RSS, last 24h) ===")
    if data["news"]:
        for item in data["news"]:
            lines.append(f"- [{item['source']}] {item['title']}")
            if item["link"]:
                lines.append(f"  link: {item['link']}")
            if item["summary"]:
                lines.append(f"  summary: {item['summary']}")
    else:
        lines.append("(no news fetched)")

    lines.append("\n=== CVEs (NVD, last 24h) ===")
    if data["cves"]:
        for c in data["cves"]:
            score = f"{c['score']:.1f}" if c["score"] else "N/A"
            lines.append(f"- {c['id']} (CVSS {score} {c['severity']}) {c['link']}")
            if c["description"]:
                lines.append(f"  {c['description'][:400]}")
    else:
        lines.append("(no CVEs fetched)")

    lines.append("\n=== INTERNSHIP POSTINGS (Indeed RSS) ===")
    if data["jobs"]:
        for j in data["jobs"]:
            lines.append(f"- {j['title']} [{j['query']}]")
            if j["link"]:
                lines.append(f"  link: {j['link']}")
    else:
        lines.append("(no job postings fetched — Indeed RSS may be down)")

    return "\n".join(lines)


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
        max_tokens=2000,
    )
    content = response.choices[0].message.content
    logger.info("Received %d chars of summary", len(content or ""))
    return content.strip()


def fallback_markdown(data):
    """Build a plain briefing from raw data when the AI call fails."""
    lines = ["## ⚠️ AI summarization unavailable", "", "Raw fetched data below.", ""]

    lines.append("## 🔥 TOP STORIES")
    for item in data["news"][:15]:
        lines.append(f"- **[{item['title']}]({item['link']})** — {item['source']}")
    if not data["news"]:
        lines.append("Nothing fetched today.")

    lines.append("\n## 🚨 CVEs TO KNOW")
    for c in data["cves"][:20]:
        score = f"{c['score']:.1f}" if c["score"] else "N/A"
        lines.append(f"- **[{c['id']}]({c['link']})** (CVSS {score} {c['severity']})")
    if not data["cves"]:
        lines.append("Nothing fetched today.")

    lines.append("\n## 💼 INTERNSHIP OPPORTUNITIES")
    for j in data["jobs"]:
        lines.append(f"- [{j['title']}]({j['link']}) — {j['query']}")
    if not data["jobs"]:
        lines.append("No postings fetched today.")

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
      · {news} news / {cves} CVEs / {jobs} jobs fetched
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
        jobs=len(data["jobs"]),
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
        markdown_text = summarize(data)
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
