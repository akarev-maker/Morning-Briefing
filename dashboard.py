"""
dashboard.py — persist a daily snapshot and render the static GitHub Pages site.

The briefing is otherwise ephemeral; this records a small snapshot each run to
`state/history.json` and rebuilds `docs/index.html` — a self-contained (no CDN,
no JS) dark dashboard showing trends over time plus today's numbers. Published
via GitHub Pages from the repo's `/docs` folder.
"""

import html
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("briefing.dashboard")

HISTORY_PATH = os.path.join("state", "history.json")
DOCS_DIR = "docs"
DASHBOARD_PATH = os.path.join(DOCS_DIR, "index.html")
MAX_HISTORY_DAYS = 180

# One coherent, dark-mode-legible palette (kept small and consistent).
C_BLUE = "#58a6ff"
C_GREEN = "#3fb950"
C_RED = "#f85149"
C_PURPLE = "#bc8cff"
C_AMBER = "#d29922"
C_GRID = "#21262d"
C_MUTED = "#8b949e"


# ---------------------------------------------------------------------------
# History persistence
# ---------------------------------------------------------------------------
def snapshot(data):
    """Build today's compact snapshot from a fetched-data dict."""
    cves = data.get("cves", [])
    kev = data.get("kev", [])
    jobs = data.get("jobs", [])
    htb = data.get("htb") or {}
    return {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "news": len(data.get("news", [])),
        "cves": len(cves),
        "high_cves": sum(1 for c in cves if c.get("score", 0) >= 7.0),
        "kev": len(kev),
        "kev_poc": sum(1 for k in kev if k.get("pocs")),
        "jobs": len(jobs),
        "new_jobs": sum(1 for j in jobs if j.get("is_new")),
        "ma_remote_jobs": sum(1 for j in jobs if j.get("rank", 2) <= 1),
        "ctf": len(data.get("ctf", [])),
        "htb_points": htb.get("points", 0) or 0,
        "htb_rank": htb.get("rank", "") or "",
        "htb_user_owns": htb.get("user_owns", 0) or 0,
        "htb_system_owns": htb.get("system_owns", 0) or 0,
    }


def load_history(path=HISTORY_PATH):
    try:
        with open(path, encoding="utf-8") as f:
            hist = json.load(f)
            return hist if isinstance(hist, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def record_snapshot(data, path=HISTORY_PATH):
    """Add/replace today's snapshot in the history file; returns the full history."""
    hist = load_history(path)
    today = snapshot(data)
    hist = [h for h in hist if h.get("date") != today["date"]]
    hist.append(today)
    hist.sort(key=lambda h: h.get("date", ""))
    hist = hist[-MAX_HISTORY_DAYS:]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(hist, f, indent=1)
    except OSError as exc:
        logger.warning("Could not save history to %s: %s", path, exc)
    return hist


# ---------------------------------------------------------------------------
# SVG chart helpers (no JS, no external libs)
# ---------------------------------------------------------------------------
def _line_chart(series, color, width=600, height=140, unit=""):
    """series: list of (date, value). Returns an inline SVG string."""
    vals = [float(v) for _, v in series]
    if not vals:
        return '<p style="color:#8b949e">No data yet.</p>'
    mn, mx = min(vals), max(vals)
    span = (mx - mn) or 1.0
    n = len(vals)
    left, right, top, bottom = 8, 8, 12, 22
    plot_w, plot_h = width - left - right, height - top - bottom

    def px(i):
        return left + (i / (n - 1) if n > 1 else 0.5) * plot_w

    def py(v):
        return top + (1 - (v - mn) / span) * plot_h

    pts = [(px(i), py(v)) for i, v in enumerate(vals)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = (
        f"{pts[0][0]:.1f},{top + plot_h:.1f} "
        + line
        + f" {pts[-1][0]:.1f},{top + plot_h:.1f}"
    )
    dots = ""
    if n == 1:
        dots = f'<circle cx="{pts[0][0]:.1f}" cy="{pts[0][1]:.1f}" r="4" fill="{color}"/>'
    last_x, last_y = pts[-1]
    last_val = vals[-1]
    label = f"{int(last_val) if last_val == int(last_val) else last_val}{unit}"
    return f"""<svg viewBox="0 0 {width} {height}" width="100%" preserveAspectRatio="none"
       role="img" style="display:block">
  <line x1="{left}" y1="{top}" x2="{width - right}" y2="{top}" stroke="{C_GRID}" stroke-width="1"/>
  <line x1="{left}" y1="{top + plot_h:.0f}" x2="{width - right}" y2="{top + plot_h:.0f}" stroke="{C_GRID}" stroke-width="1"/>
  <polygon points="{area}" fill="{color}" opacity="0.12"/>
  <polyline points="{line}" fill="none" stroke="{color}" stroke-width="2"
            stroke-linejoin="round" stroke-linecap="round"/>
  {dots}
  <circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="3" fill="{color}"/>
  <text x="{width - right}" y="{top + 4}" text-anchor="end" font-size="12"
        fill="{color}" font-weight="700">{label}</text>
  <text x="{left}" y="{height - 6}" font-size="10" fill="{C_MUTED}">{series[0][0]}</text>
  <text x="{width - right}" y="{height - 6}" text-anchor="end" font-size="10"
        fill="{C_MUTED}">{series[-1][0]}</text>
</svg>"""


def _series(history, key):
    return [(h.get("date", ""), h.get(key, 0) or 0) for h in history]


# ---------------------------------------------------------------------------
# Page rendering
# ---------------------------------------------------------------------------
def _tile(value, label, color=C_BLUE):
    return f"""<div class="tile">
      <div class="tile-val" style="color:{color}">{value}</div>
      <div class="tile-label">{html.escape(str(label))}</div>
    </div>"""


def _chart_card(title, subtitle, svg):
    return f"""<div class="card">
      <div class="card-title">{html.escape(title)}</div>
      <div class="card-sub">{html.escape(subtitle)}</div>
      {svg}
    </div>"""


def _internships_table(jobs):
    if not jobs:
        return "<p style='color:#8b949e'>No active security internships today.</p>"
    rows = []
    for j in jobs:
        new = '<span class="new">NEW</span> ' if j.get("is_new") else ""
        title = html.escape(j.get("title", ""))
        link = j.get("link", "")
        safe_link = link if link.startswith(("http://", "https://")) else ""
        title_html = (
            f'<a href="{html.escape(safe_link)}">{title}</a>' if safe_link else title
        )
        rows.append(
            f"<tr><td>{new}{title_html}</td>"
            f"<td>{html.escape(j.get('company', ''))}</td>"
            f"<td>{html.escape(j.get('location_str', ''))}</td>"
            f"<td>{html.escape(str(j.get('term', '')))}</td></tr>"
        )
    return f"""<table>
      <thead><tr><th>Role</th><th>Company</th><th>Location</th><th>Term</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>"""


def render_dashboard(history, data, path=DASHBOARD_PATH):
    """Write the static dashboard HTML. Returns the path written."""
    latest = history[-1] if history else snapshot(data)
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tiles = "".join(
        [
            _tile(latest["cves"], "CVEs today", C_BLUE),
            _tile(latest["kev"], "Actively exploited (KEV)", C_RED),
            _tile(latest["kev_poc"], "With public PoC", C_AMBER),
            _tile(latest["jobs"], "Internships", C_GREEN),
            _tile(latest["new_jobs"], "New today", C_GREEN),
            _tile(latest["ctf"], "Upcoming CTFs", C_PURPLE),
            _tile(latest.get("htb_points", 0), "HTB points", C_PURPLE),
        ]
    )

    cards = "".join(
        [
            _chart_card(
                "Internships tracked",
                "Active security internships per day",
                _line_chart(_series(history, "jobs"), C_GREEN),
            ),
            _chart_card(
                "CVEs published",
                "NVD CVEs per day (CVSS 7.0+ included)",
                _line_chart(_series(history, "cves"), C_BLUE),
            ),
            _chart_card(
                "Actively-exploited (CISA KEV)",
                "New KEV entries per day",
                _line_chart(_series(history, "kev"), C_RED),
            ),
            _chart_card(
                "HackTheBox points",
                "Your labs progress over time",
                _line_chart(_series(history, "htb_points"), C_PURPLE, unit=" pts"),
            ),
        ]
    )

    table = _internships_table(data.get("jobs", []))
    days = len(history)

    return _write(
        path,
        f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Cyber Briefing Dashboard</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin:0; background:#0d1117; color:#c9d1d9;
    font-family:'SFMono-Regular',Consolas,Menlo,monospace; line-height:1.5;
  }}
  .wrap {{ max-width:920px; margin:0 auto; padding:28px 20px 60px; }}
  h1 {{ color:{C_BLUE}; font-size:22px; margin:0 0 2px; letter-spacing:.5px; }}
  .updated {{ color:{C_MUTED}; font-size:12px; margin-bottom:22px; }}
  .tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
            gap:10px; margin-bottom:26px; }}
  .tile {{ background:#161b22; border:1px solid {C_GRID}; border-radius:10px;
           padding:14px; text-align:center; }}
  .tile-val {{ font-size:26px; font-weight:800; }}
  .tile-label {{ font-size:11px; color:{C_MUTED}; margin-top:4px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
           gap:14px; margin-bottom:26px; }}
  .card {{ background:#161b22; border:1px solid {C_GRID}; border-radius:12px; padding:16px; }}
  .card-title {{ font-size:14px; font-weight:700; color:#e6edf3; }}
  .card-sub {{ font-size:11px; color:{C_MUTED}; margin:2px 0 12px; }}
  h2 {{ font-size:15px; color:{C_BLUE}; border-bottom:1px solid {C_GRID};
        padding-bottom:8px; margin:30px 0 12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid {C_GRID};
            vertical-align:top; }}
  th {{ color:{C_MUTED}; font-weight:600; font-size:11px; text-transform:uppercase; }}
  a {{ color:#79c0ff; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  .new {{ background:{C_GREEN}; color:#0d1117; font-size:10px; font-weight:800;
          padding:1px 5px; border-radius:4px; }}
  .foot {{ color:#6e7681; font-size:11px; margin-top:34px; border-top:1px solid {C_GRID};
           padding-top:14px; }}
  .overflow {{ overflow-x:auto; }}
</style></head>
<body><div class="wrap">
  <h1>&#128272; Cyber Briefing Dashboard</h1>
  <div class="updated">Updated {updated} · {days} day(s) of history</div>

  <div class="tiles">{tiles}</div>

  <div class="grid">{cards}</div>

  <h2>&#128188; Current internships</h2>
  <div class="overflow">{table}</div>

  <div class="foot">
    Auto-generated daily by
    <a href="https://github.com/akarev-maker/Morning-Briefing">Morning-Briefing</a>
    · GitHub Actions + GitHub Models. Charts fill in as history accumulates.
  </div>
</div></body></html>""",
    )


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def update(data):
    """Record today's snapshot and rebuild the dashboard. Never raises."""
    try:
        history = record_snapshot(data)
        render_dashboard(history, data)
        logger.info("Dashboard updated (%d day(s) of history).", len(history))
    except Exception as exc:  # noqa: BLE001 — dashboard must never break the run
        logger.warning("Dashboard update failed: %s", exc)
