"""
render.py: build the email, HTML and plain text, from the day's picks.

Everything shown came from an outside source (or, from Task 7, the model), so
nothing is trusted: all text goes through html.escape and every link through
fetcher.safe_url. HTML is built directly instead of converting Markdown, so
there is no Markdown syntax for a hostile headline to abuse.

Email clients are not browsers. Gmail drops <style> blocks in some views and
ignores most modern CSS, so the layout is a 640px table with inline styles.
"""

import html
from datetime import date

from dateutil import parser as dateparser

import fetcher

FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
PAGE_BG = "#f4f4f5"
CARD_BG = "#ffffff"
INK = "#18181b"
BODY = "#3f3f46"
MUTED = "#71717a"
RULE = "#e4e4e7"
LINK = "#1d4ed8"

# (background, text) per tag color.
TAG_COLORS = {
    "red": ("#fee2e2", "#991b1b"),
    "amber": ("#fef3c7", "#92400e"),
    "green": ("#dcfce7", "#166534"),
    "blue": ("#dbeafe", "#1e40af"),
}

SUMMARY_CHARS = 240
NVD_URL = "https://nvd.nist.gov/vuln/detail/"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _e(text):
    """Escape text for HTML, quotes included (it is also used in attributes)."""
    return html.escape(str(text if text is not None else ""), quote=True)


def _link(text, url, color=LINK, weight="inherit"):
    url = fetcher.safe_url(url)
    if not url:
        return _e(text)
    return (
        f'<a href="{_e(url)}" style="color:{color};text-decoration:none;'
        f'font-weight:{weight};">{_e(text)}</a>'
    )


def _tag_html(label, color):
    bg, fg = TAG_COLORS[color]
    return (
        f'<span style="display:inline-block;background:{bg};color:{fg};font-size:11px;'
        f'font-weight:600;padding:2px 7px;border-radius:4px;margin:0 4px 4px 0;">'
        f"{_e(label)}</span>"
    )


def _short(text, limit=SUMMARY_CHARS):
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


def _day(d):
    return f"{d:%a} {d:%b} {d.day}"


def _relative(days):
    if days == 0:
        return "today"
    if days == 1:
        return "tomorrow"
    return f"in {days} days" if days > 1 else ""


def _date_range(start, end):
    end = end or start
    if start == end:
        return _day(start)
    if (start.year, start.month) == (end.year, end.month):
        return f"{start:%b} {start.day}–{end.day}"
    return f"{start:%b} {start.day} – {end:%b} {end.day}"


# ---------------------------------------------------------------------------
# Content: each returns a dict of display fields shared by HTML and text
# ---------------------------------------------------------------------------
def story_tags(story):
    tags = []
    if story.get("exploited"):
        tags.append(("Exploited in the wild (CISA KEV)", "red"))
    if any(c.get("ransomware") for c in story.get("cve_info", [])):
        tags.append(("Used in ransomware", "red"))
    if story.get("has_poc"):
        tags.append(("Public exploit code", "amber"))
    return tags


def story_meta(story):
    """"Bleeping Computer, Dark Reading · 2 outlets · 505 points on HN"."""
    parts = [", ".join(story.get("sources") or [story.get("source", "")])]
    if (story.get("coverage") or 1) > 1:
        parts.append(f"{story['coverage']} outlets")
    if story.get("points"):
        parts.append(f"{story['points']} points on HN")
    return " · ".join(p for p in parts if p)


def story_body(story):
    """The model's "why it matters" line if there is one, else the summary."""
    return story.get("why") or _short(story.get("summary", ""))


def hackathon_when(h, today):
    start, end = h["start"], h["end"] or h["start"]
    if h["online"] and start <= today:
        return f"Open now, ends {end:%b} {end.day}"
    rel = _relative((start - today).days)
    return _date_range(start, end) + (f" ({rel})" if rel else "")


def hackathon_meta(h):
    parts = [h["location"]]
    # Sign-up counts help compare big online events; for a campus event a
    # small number ("4 registered") just looks odd.
    if h.get("online") and h.get("registrations"):
        parts.append(f"{h['registrations']:,} registered")
    if h.get("prize"):
        parts.append(f"{h['prize']} in prizes")
    parts.append(h["source"])
    return " · ".join(p for p in parts if p)


def hackathon_tags(h):
    tags = []
    if h.get("school"):
        tags.append((f"Worth applying: {h['school']}", "green"))
    if h.get("starting_soon"):
        tags.append(("Starting soon" + (" (reminder)" if h.get("reminder") else ""), "blue"))
    return tags


def ctf_line(e, today):
    """(when, details) for one CTF, e.g. ("Sat Nov 22 (in 4 days)", "Online · Jeopardy")."""
    when = e.get("start", "")[:10]
    try:
        start = dateparser.parse(e["start"]).date()
        rel = _relative((start - today).days)
        when = _day(start) + (f" ({rel})" if rel else "")
    except (KeyError, ValueError, TypeError, OverflowError):
        pass
    place = e.get("location") if e.get("onsite") else "Online"
    details = " · ".join(p for p in (place, e.get("format")) if p)
    return when, details


def source_summary(status):
    """("13 of 14 sources OK", ["MLH: returned nothing (possible failure)"])."""
    problems = []
    for name in sorted(status):
        s = status[name]
        if s["state"] == "failed":
            problems.append(f"{name}: failed")
        elif s["state"] == "partial":
            problems.append(f"{name}: partly failed ({s['count']} items)")
        elif s["state"] == "empty":
            problems.append(f"{name}: returned nothing (possible failure)")
    total = len(status)
    if not problems:
        return f"All {total} sources OK", []
    return f"{total - len(problems)} of {total} sources OK", problems


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def _section(title, inner):
    return (
        f'<tr><td style="padding:30px 32px 0;">'
        f'<div style="font-size:12px;font-weight:700;letter-spacing:1.2px;'
        f"text-transform:uppercase;color:{MUTED};border-bottom:1px solid {RULE};"
        f'padding-bottom:8px;">{_e(title)}</div>{inner}</td></tr>'
    )


def _empty(text):
    return f'<div style="padding:14px 0;font-size:14px;color:{MUTED};">{_e(text)}</div>'


def _item(title_html, meta="", body="", tags=(), extra=""):
    out = [f'<div style="padding:14px 0;border-bottom:1px solid {RULE};">']
    out.append(f'<div style="font-size:16px;line-height:1.35;">{title_html}</div>')
    if meta:
        out.append(f'<div style="font-size:12px;color:{MUTED};margin-top:3px;">{_e(meta)}</div>')
    if body:
        out.append(
            f'<div style="font-size:14px;line-height:1.55;color:{BODY};margin-top:6px;">'
            f"{_e(body)}</div>"
        )
    if tags:
        out.append('<div style="margin-top:8px;">'
                   + "".join(_tag_html(label, color) for label, color in tags) + "</div>")
    out.append(extra)
    out.append("</div>")
    return "".join(out)


def _cve_html(story):
    links = []
    for c in story.get("cve_info", []):
        link = _link(c["id"], NVD_URL + c["id"], color=MUTED)
        if c.get("pocs"):
            link += " (" + _link("exploit", c["pocs"][0]["url"], color=MUTED) + ")"
        links.append(link)
    if not links:
        return ""
    return f'<div style="font-size:12px;color:{MUTED};margin-top:2px;">{" · ".join(links)}</div>'


def _story_html(story):
    title = _link(story["title"], story["link"], color=INK, weight="600")
    extra = _cve_html(story)
    if story.get("comments"):
        extra += (f'<div style="font-size:12px;margin-top:2px;">'
                  f'{_link("HN discussion", story["comments"], color=MUTED)}</div>')
    return _item(title, story_meta(story), story_body(story), story_tags(story), extra)


def _stories_html(stories, empty_text):
    if not stories:
        return _empty(empty_text)
    return "".join(_story_html(s) for s in stories)


def _project_html(project):
    rows = [
        f'<div style="font-size:18px;font-weight:700;color:{INK};">{_e(project["title"])}</div>',
        f'<div style="font-size:14px;line-height:1.6;color:{BODY};margin-top:8px;">'
        f'{_e(project["pitch"])}</div>',
    ]
    if project.get("milestones"):
        items = "".join(f'<li style="margin:4px 0;">{_e(m)}</li>' for m in project["milestones"])
        rows.append(f'<ol style="font-size:14px;line-height:1.5;color:{BODY};'
                    f'margin:10px 0 0;padding-left:20px;">{items}</ol>')
    if project.get("stack"):
        rows.append(f'<div style="font-size:12px;color:{MUTED};margin-top:10px;">'
                    f'Stack: {_e(", ".join(project["stack"]))}</div>')
    if project.get("inspired_by"):
        links = ", ".join(_link(s["title"], s["link"], color=MUTED)
                          for s in project["inspired_by"])
        rows.append(f'<div style="font-size:12px;color:{MUTED};margin-top:4px;">'
                    f"Inspired by: {links}</div>")
    return (f'<div style="margin-top:14px;padding:18px 20px;background:#f8fafc;'
            f'border:1px solid {RULE};border-left:3px solid {LINK};border-radius:6px;">'
            + "".join(rows) + "</div>")


def _hackathons_html(hackathons, today):
    out = []
    for label, group in (("Near you", hackathons.get("nearby", [])),
                         ("Online", hackathons.get("online", []))):
        if not group:
            continue
        out.append(f'<div style="font-size:13px;font-weight:600;color:{INK};'
                   f'margin-top:16px;">{_e(label)}</div>')
        for h in group:
            title = _link(h["name"], h["url"], color=INK, weight="600")
            out.append(_item(title, hackathon_meta(h), hackathon_when(h, today),
                             hackathon_tags(h)))
    return "".join(out) or _empty("No new hackathons today.")


def _ctfs_html(events, today):
    if not events:
        return _empty("No CTFs found for the next three weeks.")
    rows = []
    for e in events:
        when, details = ctf_line(e, today)
        rows.append(
            f'<div style="padding:9px 0;border-bottom:1px solid {RULE};font-size:14px;">'
            f'{_link(e["title"], e.get("url"), color=INK, weight="600")}'
            f'<div style="font-size:12px;color:{MUTED};margin-top:2px;">'
            f'{_e(when)}{" · " + _e(details) if details else ""}</div></div>'
        )
    return "".join(rows)


def _footer_html(b):
    head, problems = source_summary(b.get("status", {}))
    ranking = (f"Stories picked by {b.get('model') or 'Gemini'}." if b.get("edited")
               else "Stories ranked by how many outlets covered them (AI editor unavailable).")
    lines = [f"{_e(head)}. {_e(ranking)}"]
    for p in problems:
        lines.append(f'<span style="color:{TAG_COLORS["amber"][1]};">{_e(p)}</span>')
    return (f'<tr><td style="padding:28px 32px 30px;font-size:12px;line-height:1.6;'
            f'color:{MUTED};">' + "<br>".join(lines) + "</td></tr>")


def render_html(b, today):
    sections = []
    if b.get("degraded"):
        sections.append(
            '<tr><td style="padding:20px 32px 0;"><div style="background:#fef3c7;'
            'color:#92400e;padding:12px 14px;border-radius:6px;font-size:14px;">'
            "No news was fetched today. That usually means the feeds failed, not "
            "that nothing happened. The footer lists which sources had problems."
            "</div></td></tr>"
        )
    sections.append(_section("Cybersecurity", _stories_html(b.get("cyber", []),
                                                            "No new security stories today.")))
    sections.append(_section("AI and machine learning",
                             _stories_html(b.get("ai", []), "No new AI stories today.")))
    if b.get("project"):
        sections.append(_section("Project idea", _project_html(b["project"])))
    sections.append(_section("Hackathons", _hackathons_html(b.get("hackathons", {}), today)))
    sections.append(_section("CTFs", _ctfs_html(b.get("ctf", []), today)))

    header = (
        f'<tr><td style="padding:28px 32px 0;">'
        f'<div style="font-size:22px;font-weight:700;color:{INK};">Morning Briefing</div>'
        f'<div style="font-size:13px;color:{MUTED};margin-top:2px;">'
        f"{_e(f'{today:%A}, {today:%B} {today.day}, {today:%Y}')}</div></td></tr>"
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"></head>'
        f'<body style="margin:0;padding:0;background:{PAGE_BG};">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{PAGE_BG};"><tr><td align="center" style="padding:24px 12px;">'
        f'<table role="presentation" width="640" cellpadding="0" cellspacing="0" '
        f'style="max-width:640px;width:100%;background:{CARD_BG};border-radius:8px;'
        f'font-family:{FONT};color:{INK};">'
        + header + "".join(sections) + _footer_html(b)
        + "</table></td></tr></table></body></html>"
    )


# ---------------------------------------------------------------------------
# Plain text (for clients that don't show HTML, and for previews)
# ---------------------------------------------------------------------------
def _text_heading(title):
    return f"\n\n{title.upper()}\n{'-' * len(title)}"


def _text_story(n, s):
    lines = [f"{n}. {s['title']}", f"   {story_meta(s)}"]
    body = story_body(s)
    if body:
        lines.append(f"   {body}")
    tags = story_tags(s)
    if tags:
        lines.append("   " + " ".join(f"[{label}]" for label, _ in tags))
    for c in s.get("cve_info", []):
        poc = f" (exploit: {c['pocs'][0]['url']})" if c.get("pocs") else ""
        lines.append(f"   {c['id']}: {NVD_URL}{c['id']}{poc}")
    if s.get("link"):
        lines.append(f"   {s['link']}")
    return "\n".join(lines)


def render_text(b, today):
    out = [f"MORNING BRIEFING\n{today:%A}, {today:%B} {today.day}, {today:%Y}"]
    if b.get("degraded"):
        out.append("\nNo news was fetched today; the feeds probably failed.")

    for title, key, empty in (("Cybersecurity", "cyber", "No new security stories today."),
                              ("AI and machine learning", "ai", "No new AI stories today.")):
        out.append(_text_heading(title))
        stories = b.get(key, [])
        if stories:
            out.append("\n\n".join(_text_story(i, s) for i, s in enumerate(stories, 1)))
        else:
            out.append(empty)

    project = b.get("project")
    if project:
        out.append(_text_heading("Project idea"))
        out.append(project["title"])
        out.append(project["pitch"])
        out.extend(f"  {i}. {m}" for i, m in enumerate(project.get("milestones", []), 1))
        if project.get("stack"):
            out.append("Stack: " + ", ".join(project["stack"]))
        for s in project.get("inspired_by", []):
            out.append(f"Inspired by: {s['title']} {s['link']}")

    out.append(_text_heading("Hackathons"))
    hackathons = b.get("hackathons", {})
    any_hackathons = False
    for label, group in (("Near you", hackathons.get("nearby", [])),
                         ("Online", hackathons.get("online", []))):
        if group:
            any_hackathons = True
            out.append(f"{label}:")
        for h in group:
            tags = " ".join(f"[{t}]" for t, _ in hackathon_tags(h))
            out.append(f"- {h['name']}: {hackathon_when(h, today)}")
            out.append(f"  {hackathon_meta(h)}" + (f" {tags}" if tags else ""))
            if h.get("url"):
                out.append(f"  {h['url']}")
    if not any_hackathons:
        out.append("No new hackathons today.")

    out.append(_text_heading("CTFs"))
    events = b.get("ctf", [])
    for e in events:
        when, details = ctf_line(e, today)
        out.append(f"- {e['title']}: {when}" + (f" · {details}" if details else ""))
        if e.get("url"):
            out.append(f"  {e['url']}")
    if not events:
        out.append("No CTFs found for the next three weeks.")

    head, problems = source_summary(b.get("status", {}))
    out.append(f"\n--\n{head}.")
    out.extend(problems)
    return "\n".join(out) + "\n"


def subject(today):
    return f"Morning Briefing · {today:%a} {today:%b} {today.day}"


def render(b, today=None):
    """(subject, html, text) for the briefing dict `b`."""
    today = today or date.today()
    return subject(today), render_html(b, today), render_text(b, today)
