"""
briefing.py: entry point. Fetch data, have Gemini write it up, email it.

If the Gemini call fails, a plain briefing is built straight from the fetched
data, so a model outage never means a missed email.
"""

import html as html_lib
import logging
import os
import re
import smtplib
import ssl
import sys
import traceback
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
# Gemini through its OpenAI-compatible endpoint. The "-latest" alias always
# points at the newest Flash model, so retired versions never break the job.
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/openai/"
MODEL = "gemini-flash-latest"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

SYSTEM_PROMPT = """\
You are the editor of a short daily cybersecurity newsletter for a computer
science student interested in security and AI. Only summarize what you are
given; never invent facts or links. Write in Markdown.
"""

OUTPUT_INSTRUCTIONS = """\
Write exactly these two Markdown sections, with these `##` headings:

## Top Stories
The most notable news items. For each: a bold headline linked to the source,
then one or two sentences on what happened and why it matters.

## Quick Hits
One-line bullets for other items worth knowing about.

Do not write any other sections. The CTF list is added separately.
"""

QUICK_HITS_HEADING = "## Quick Hits"
CTF_HEADING = "## Upcoming CTFs"

PROMPT_NEWS_CAP = 60


def _md(text):
    """Escape Markdown control characters in untrusted text.

    Stops a feed or CTF title containing `[x](y)` or `*` from forging a link or
    breaking the layout of a section built in code.
    """
    if not text:
        return ""
    out = str(text)
    for ch in ("\\", "`", "*", "_", "[", "]", "<", ">"):
        out = out.replace(ch, "\\" + ch)
    return out


_safe_url = fetcher.safe_url


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------
def _format_data_for_prompt(data):
    lines = ["=== NEWS (last 24h) ==="]
    if data["news"]:
        for item in data["news"][:PROMPT_NEWS_CAP]:
            lines.append(f"- [{item['source']}] {item['title']}")
            if item["link"]:
                lines.append(f"  link: {item['link']}")
            if item["summary"]:
                lines.append(f"  summary: {item['summary'][:220]}")
    else:
        lines.append("(no news fetched)")
    return "\n".join(lines)


def summarize(data):
    """Ask Gemini for the Markdown briefing. Raises on any failure."""
    token = os.environ.get("GEMINI_API_KEY")
    if not token:
        raise RuntimeError("GEMINI_API_KEY is not set")

    client = OpenAI(base_url=GEMINI_ENDPOINT, api_key=token)
    user_content = (
        OUTPUT_INSTRUCTIONS
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
        # Flash models "think" by default and those hidden tokens count against
        # max_tokens. This is summarizing, not reasoning, so keep thinking low.
        reasoning_effort="low",
        max_tokens=8000,
    )
    choice = response.choices[0]
    content = (choice.message.content or "").strip()
    if not content:
        # Gemini returns an empty message when it stops before writing anything
        # (out of tokens, or a safety block). Say why instead of crashing on None.
        raise RuntimeError(
            "model returned an empty response "
            f"(finish_reason={getattr(choice, 'finish_reason', None)!r})"
        )
    logger.info("Received %d chars of summary", len(content))
    return content


# ---------------------------------------------------------------------------
# Sections built in code
# ---------------------------------------------------------------------------
def build_ctf_markdown(events):
    """The CTF section, built from CTFtime data (never by the model)."""
    lines = [CTF_HEADING]
    if not events:
        lines.append("No upcoming events found.")
        return "\n".join(lines)
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
        place = "Online" if not e.get("onsite") else _md(e.get("location", "On-site"))
        fmt = f" · {_md(e['format'])}" if e.get("format") else ""
        name = _md(e["title"])
        url = _safe_url(e.get("url"))
        title = f"**[{name}]({url})**" if url else f"**{name}**"
        lines.append(f"- {title}: {when}{rel} · {place}{fmt}")
    return "\n".join(lines)


def assemble_briefing(ai_markdown, data):
    """Insert the code-built CTF section into the model's text, before Quick Hits."""
    text = ai_markdown

    # If the model wrote a CTF section anyway, remove it so there's only one.
    while CTF_HEADING in text:
        start = text.index(CTF_HEADING)
        after = text.find("\n## ", start + 1)
        text = text[:start] + (text[after + 1 :] if after != -1 else "")

    block = build_ctf_markdown(data.get("ctf", []))
    if QUICK_HITS_HEADING in text:
        idx = text.index(QUICK_HITS_HEADING)
        return text[:idx].rstrip() + "\n\n" + block + "\n\n" + text[idx:]
    return text.rstrip() + "\n\n" + block + "\n"


def fallback_markdown(data):
    """A plain briefing from raw data, used when the Gemini call fails."""
    lines = ["*AI summary unavailable today. Stories are listed as fetched.*", ""]
    lines.append("## Top Stories")
    for item in data["news"][:15]:
        lines.append(
            f"- **[{_md(item['title'])}]({_safe_url(item['link'])})**: {_md(item['source'])}"
        )
    if not data["news"]:
        lines.append("Nothing fetched today.")
    lines.append("")
    lines.append(build_ctf_markdown(data.get("ctf", [])))
    return "\n".join(lines)


def degraded_banner(data):
    """A warning when every news feed came back empty.

    At least one of the four feeds publishes something every day, so zero
    stories means the fetches failed, not that it was a quiet day.
    """
    if not data.get("news"):
        logger.warning("Degraded run: 0 news items (likely a widespread fetch failure)")
        return (
            "> **Heads up:** no news was fetched today. This usually means the "
            "feeds failed, not that nothing happened. Check the Actions logs.\n\n"
        )
    return ""


# ---------------------------------------------------------------------------
# Email rendering
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """\
<div style="margin:0;padding:0;background-color:#0d1117;">
  <div style="max-width:680px;margin:0 auto;padding:24px 20px;
              font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
              color:#c9d1d9;background-color:#0d1117;">
    <div style="border-bottom:1px solid #21262d;padding-bottom:16px;margin-bottom:8px;">
      <div style="font-size:20px;font-weight:bold;color:#58a6ff;letter-spacing:0.5px;">
        MORNING BRIEFING
      </div>
      <div style="font-size:13px;color:#8b949e;margin-top:4px;">{date_str}</div>
    </div>
    <div class="briefing-body" style="font-size:14px;line-height:1.6;">
      {body}
    </div>
    <div style="border-top:1px solid #21262d;margin-top:28px;padding-top:14px;
                font-size:11px;color:#6e7681;">
      {news} news items · {ctf} CTFs
    </div>
  </div>
</div>
"""

EMAIL_STYLES = """\
<style>
  .briefing-body h2 {
    color:#58a6ff; font-size:16px; margin:26px 0 10px 0;
    padding-bottom:6px; border-bottom:1px solid #21262d;
  }
  .briefing-body a { color:#79c0ff; text-decoration:none; }
  .briefing-body strong { color:#e6edf3; }
  .briefing-body ul { padding-left:20px; margin:8px 0; }
  .briefing-body li { margin:6px 0; }
  .briefing-body p { margin:8px 0; }
</style>
"""

# python-markdown always writes double-quoted href attributes.
_HREF_RE = re.compile(r'(<a\s[^>]*?href=")([^"]*)(")', re.IGNORECASE)


def sanitize_html_links(html_text):
    """Replace any non-http(s) href in the rendered HTML with "#".

    The model writes its own Markdown links and could echo or invent a bad URL,
    so this is the last check before sending. The href is unescaped and
    stripped of whitespace first, because `&#106;avascript:` and
    `java\\tscript:` both work as links in mail clients.
    """

    def _neutralize(match):
        url = re.sub(r"[\s\x00-\x1f\x7f]+", "", html_lib.unescape(match.group(2)))
        if url.lower().startswith(("http://", "https://")):
            return match.group(0)
        logger.warning("Stripped non-http(s) link from briefing: %.80r", match.group(2))
        return match.group(1) + "#" + match.group(3)

    return _HREF_RE.sub(_neutralize, html_text)


def render_html(markdown_text, data, date_str):
    body_html = sanitize_html_links(
        md.markdown(markdown_text, extensions=["extra", "sane_lists"])
    )
    inner = HTML_TEMPLATE.format(
        date_str=date_str,
        body=body_html,
        news=len(data["news"]),
        ctf=len(data.get("ctf", [])),
    )
    return EMAIL_STYLES + inner


def render_plain_text(markdown_text, date_str):
    return f"MORNING BRIEFING, {date_str}\n{'=' * 40}\n\n{markdown_text}"


# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------
def _email_creds():
    return (
        os.environ.get("EMAIL_SENDER"),
        os.environ.get("EMAIL_RECIPIENT"),
        os.environ.get("EMAIL_PASSWORD"),
    )


def send_email(subject, html_body, text_body):
    sender, recipient, password = _email_creds()
    missing = [
        name
        for name, val in zip(
            ("EMAIL_SENDER", "EMAIL_RECIPIENT", "EMAIL_PASSWORD"), (sender, recipient, password)
        )
        if not val
    ]
    if missing:
        raise RuntimeError(f"Missing email env var(s): {', '.join(missing)}")

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    # Mail clients show the last part they support, so HTML goes last.
    message.attach(MIMEText(text_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    logger.info("Sending email…")
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
        server.login(sender, password)
        server.sendmail(sender, recipient, message.as_string())
    logger.info("Email sent.")


def send_failure_email(error_text):
    """Best-effort alert when the run crashes.

    Can't help if SMTP itself is the problem. The workflow's open-an-issue step
    covers that case.
    """
    sender, recipient, password = _email_creds()
    if not (sender and recipient and password):
        logger.error("Cannot send failure alert: email env vars missing.")
        return

    when = datetime.now().strftime("%A, %B %d, %Y at %H:%M")
    body = (
        f"The morning briefing failed on {when}.\n\n"
        f"Error:\n{error_text}\n\n"
        "Check the GitHub Actions run logs for the full traceback."
    )
    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = "Morning Briefing FAILED"
    message["From"] = sender
    message["To"] = recipient
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, message.as_string())
        logger.info("Failure alert email sent.")
    except Exception as exc:  # noqa: BLE001
        logger.error("Could not send failure alert email: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    data = fetcher.fetch_all()

    try:
        markdown_text = assemble_briefing(summarize(data), data)
    except Exception as exc:  # noqa: BLE001 - still send something useful
        logger.error("AI summarization failed (%s); using fallback briefing.", exc)
        markdown_text = fallback_markdown(data)

    markdown_text = degraded_banner(data) + markdown_text

    date_str = datetime.now().strftime("%A, %B %d, %Y")
    subject = f"Morning Briefing · {date_str}"

    send_email(
        subject,
        render_html(markdown_text, data, date_str),
        render_plain_text(markdown_text, date_str),
    )
    logger.info("Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        logger.critical("Briefing run failed: %s", exc)
        send_failure_email(f"{exc}\n\n{traceback.format_exc()}")
        sys.exit(1)
