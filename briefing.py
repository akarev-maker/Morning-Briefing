"""
briefing.py: entry point. Runs the whole pipeline once.

    fetch -> curate -> drop already sent -> pick -> render -> send -> save state

    python briefing.py            send the email, then record what was sent
    python briefing.py --dry-run  write preview.html / preview.txt instead;
                                  sends nothing and records nothing

If anything crashes, a plain-text failure alert is emailed and the process
exits non-zero, so the workflow's "open an issue" step also fires.
"""

import argparse
import logging
import os
import smtplib
import ssl
import sys
import traceback
from datetime import date, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import curate
import fetcher
import hackathons
import render
import state

logger = logging.getLogger("briefing")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

STORIES_PER_SECTION = 6
PREVIEW_HTML = "preview.html"
PREVIEW_TEXT = "preview.txt"


# ---------------------------------------------------------------------------
# Building the briefing
# ---------------------------------------------------------------------------
def pick_stories(stories, per_section=STORIES_PER_SECTION):
    """The top stories per category, in curate's coverage order.

    This is the ranking when no model is involved. Task 7 puts Gemini in front
    of it and falls back to this when Gemini fails.
    """
    return {
        category: [s for s in stories if s["category"] == category][:per_section]
        for category in ("cyber", "ai")
    }


def build(today=None):
    """Fetch everything and assemble today's briefing. Sends nothing.

    Returns (briefing, keys, sent): the dict render.py draws, the sent-log keys
    for everything in it, and the sent log as loaded.
    """
    today = today or date.today()
    fetcher.reset_status()

    data = fetcher.fetch_all()
    raw_hackathons = hackathons.fetch_hackathons()
    sent = state.load_sent()

    stories = state.filter_unsent(curate.curate(data["news"], data["kev"]), sent)
    picks = pick_stories(stories)
    chosen_hackathons = hackathons.select(raw_hackathons, sent, today)

    briefing = {
        "cyber": picks["cyber"],
        "ai": picks["ai"],
        "project": None,
        "edited": False,
        "hackathons": chosen_hackathons,
        "ctf": data["ctf"],
        "status": dict(fetcher.source_status),
        "degraded": not data["news"],
    }

    # Only what is actually shown gets marked as sent. A story that didn't
    # make the cut today can still show up tomorrow.
    keys = set()
    for story in picks["cyber"] + picks["ai"]:
        keys |= state.story_keys(story)
    for h in chosen_hackathons["nearby"] + chosen_hackathons["online"]:
        keys |= hackathons.hackathon_keys(h)
    return briefing, keys, sent


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
def _email_creds():
    return (
        os.environ.get("EMAIL_SENDER"),
        os.environ.get("EMAIL_RECIPIENT"),
        os.environ.get("EMAIL_PASSWORD"),
    )


def _smtp_send(message, sender, recipient, password):
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=60) as server:
        server.login(sender, password)
        server.sendmail(sender, recipient, message.as_string())


def send_email(subject, html_body, text_body):
    sender, recipient, password = _email_creds()
    missing = [
        name
        for name, value in zip(
            ("EMAIL_SENDER", "EMAIL_RECIPIENT", "EMAIL_PASSWORD"), (sender, recipient, password)
        )
        if not value
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
    _smtp_send(message, sender, recipient, password)
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
    message = MIMEText(
        f"The morning briefing failed on {when}.\n\nError:\n{error_text}\n\n"
        "Check the GitHub Actions run logs for the full traceback.",
        "plain",
        "utf-8",
    )
    message["Subject"] = "Morning Briefing FAILED"
    message["From"] = sender
    message["To"] = recipient
    try:
        _smtp_send(message, sender, recipient, password)
        logger.info("Failure alert email sent.")
    except Exception as exc:  # noqa: BLE001
        logger.error("Could not send failure alert email: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description="Build and send the morning briefing.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=f"write {PREVIEW_HTML} and {PREVIEW_TEXT} instead of sending; record nothing",
    )
    args = parser.parse_args(argv)

    today = date.today()
    briefing, keys, sent = build(today)
    subject, html_body, text_body = render.render(briefing, today)

    if args.dry_run:
        with open(PREVIEW_HTML, "w", encoding="utf-8") as f:
            f.write(html_body)
        with open(PREVIEW_TEXT, "w", encoding="utf-8") as f:
            f.write(text_body)
        logger.info("Dry run: wrote %s and %s. Nothing sent or recorded.",
                    PREVIEW_HTML, PREVIEW_TEXT)
        return

    send_email(subject, html_body, text_body)
    # Saved only after a successful send. If the send fails, these stories
    # must not be marked as seen, or tomorrow's run would skip them too.
    state.save_sent(state.mark_sent(sent, keys, today), today=today)
    logger.info("Done.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        logger.critical("Briefing run failed: %s", exc)
        send_failure_email(f"{exc}\n\n{traceback.format_exc()}")
        sys.exit(1)
