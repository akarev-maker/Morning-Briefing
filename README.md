# 🔐 Morning Cyber Briefing

An automated morning cybersecurity briefing. Every day at **7:00 AM Eastern**,
GitHub Actions fetches the latest security news, fresh CVEs, and internship
postings, has an AI model summarize everything for a UMass Amherst cybersecurity
student on the HackTheBox Web Hacking path, and emails it to you. No manual
interaction, and your computer doesn't need to be on.

## What it does

- **Fetches** from five RSS security feeds (Krebs, The Hacker News, Bleeping
  Computer, CISA, Dark Reading), the NVD CVE API (last 24h, prioritizing CVSS
  7.0+), and Indeed RSS for penetration-testing / cybersecurity internships.
- **Summarizes** it all with the `Llama-4-Scout-17B-16E-Instruct` model via the
  **GitHub Models API** (free with GitHub Copilot / Student), tailored to your
  studies and job search.
- **Emails** a dark-themed HTML briefing (with a plain-text fallback) via Gmail.
- **Fails gracefully** — a single broken feed logs a warning and is skipped; if
  the AI call fails you still get a briefing built from the raw data.

## Project structure

| File | Purpose |
|------|---------|
| `fetcher.py` | All data fetching (RSS news, NVD CVEs, Indeed jobs). |
| `briefing.py` | AI summarization + email rendering & sending. Entry point. |
| `.github/workflows/morning.yml` | GitHub Actions schedule + manual trigger. |
| `requirements.txt` | Python dependencies. |
| `README.md` | This file. |

The briefing email is organized into: 🔥 Top Stories · 🚨 CVEs to Know ·
🎯 Relevant to Your HTB Path (incl. HackTheBox news) · 💼 Internship
Opportunities · 📌 Quick Hits.

---

## Setup

You'll need a GitHub account and a Gmail account. Total time: ~15 minutes.

### 1. Get a GitHub personal access token with **Models** permission

The AI summarization uses the GitHub Models API, authenticated with a
fine-grained personal access token (PAT).

1. Go to **GitHub → Settings → Developer settings → Personal access tokens →
   Fine-grained tokens** (or directly:
   <https://github.com/settings/personal-access-tokens/new>).
2. Click **Generate new token**.
3. Give it a name (e.g. `morning-briefing-models`) and an expiration (90 days is
   fine; you'll rotate it later).
4. Under **Permissions → Account permissions**, find **Models** and set it to
   **Read-only**. *(This is the key permission — the token needs nothing else.)*
5. Click **Generate token** and **copy it now** — you won't see it again. This
   is your `GH_MODELS_TOKEN`.

> **Note:** GitHub Models is free but rate-limited. The free tier is plenty for a
> once-a-day briefing. It's included with GitHub Copilot (free for students via
> the [Student Developer Pack](https://education.github.com/pack)).

### 2. Create a Gmail App Password (requires 2-Step Verification)

Gmail won't accept your normal password over SMTP. You need an **App Password**,
which requires 2-Step Verification (2FA) to be enabled first.

1. Turn on 2FA if you haven't: <https://myaccount.google.com/signinoptions/two-step-verification>.
2. Go to **App Passwords**: <https://myaccount.google.com/apppasswords>.
   (If the page says it's unavailable, 2FA isn't fully enabled yet — finish step 1.)
3. Enter an app name like `Morning Briefing` and click **Create**.
4. Google shows a **16-character password** (like `abcd efgh ijkl mnop`). Copy it.
   Use it **with or without spaces** — both work. This is your `EMAIL_PASSWORD`.

Your `EMAIL_SENDER` is your full Gmail address (e.g. `you@gmail.com`).
`EMAIL_RECIPIENT` is wherever you want the briefing delivered (can be the same
address).

### 3. Add the secrets to your GitHub repo

1. Push this project to a GitHub repository (public or private — either works).
2. In the repo, go to **Settings → Secrets and variables → Actions**.
3. Click **New repository secret** and add each of these:

   | Secret name | Value |
   |-------------|-------|
   | `GH_MODELS_TOKEN` | The token from step 1. |
   | `EMAIL_SENDER` | Your Gmail address. |
   | `EMAIL_RECIPIENT` | Where to deliver the briefing. |
   | `EMAIL_PASSWORD` | The 16-char Gmail App Password from step 2. |

   Names must match **exactly** — the workflow reads them by name.

### 4. Test it manually

You don't have to wait until 7 AM.

1. Go to the **Actions** tab in your repo.
2. If prompted, click **"I understand my workflows, go ahead and enable them."**
3. Select **Morning Cyber Briefing** in the left sidebar.
4. Click **Run workflow → Run workflow** (the `workflow_dispatch` trigger).
5. Watch the run. When the **Send briefing** step goes green, check your inbox.
   Click into the step logs to see how many news items / CVEs / jobs were fetched
   and any warnings about skipped feeds.

Run it locally instead (optional):

```bash
pip install -r requirements.txt
export GH_MODELS_TOKEN="…"
export EMAIL_SENDER="you@gmail.com"
export EMAIL_RECIPIENT="you@gmail.com"
export EMAIL_PASSWORD="abcd efgh ijkl mnop"
python briefing.py
# Or just inspect the fetched data without emailing:
python fetcher.py
```

---

## The schedule

The workflow runs at **12:00 UTC daily** (`cron: "0 12 * * *"`) = 7 AM EST.

- GitHub's scheduler runs on a best-effort basis and can be delayed several
  minutes (occasionally more) during peak load — this is normal.
- The cron is fixed to **UTC**, so during Eastern **Daylight** Time (EDT, roughly
  Mar–Nov) it arrives at **8 AM local**. If you want a steady 7 AM year-round,
  change the cron seasonally (`0 11 * * *` for EDT) or pick a compromise time.

To change the time, edit the `cron` line in `.github/workflows/morning.yml`.
[crontab.guru](https://crontab.guru) helps build the expression.

---

## Troubleshooting

### Indeed RSS stopped working (the internship section is empty)

Indeed's RSS endpoint (`https://www.indeed.com/rss?q=…&l=…`) is **unofficial and
unreliable** — it gets rate-limited, geo-blocked, or occasionally removed
entirely. The system is built to survive this: if the jobs fetch returns nothing,
it logs a warning and the rest of the briefing still sends.

If it stays broken, here are your options (in `fetcher.py`):

1. **Wait it out.** It often comes back on its own within a day or two. GitHub
   Actions runners share IPs, so a block can also just be temporary.
2. **Tweak the queries.** Edit `INDEED_QUERIES` in `fetcher.py` — simpler terms
   (e.g. `"cybersecurity intern"`) and broader locations sometimes get through
   when specific ones don't.
3. **Switch to a more stable job source.** Replace the Indeed logic with another
   feed the system can parse the same way:
   - **LinkedIn Jobs RSS** via a third-party generator (e.g. rss.app).
   - **We Work Remotely** security feed: `https://weworkremotely.com/categories/remote-devops-sysadmin-jobs.rss`.
   - **CyberSecJobs / Wellfound / Simplify** — many expose RSS or a simple JSON API.
   - Because `fetch_jobs()` just returns a list of `{title, link, summary, query}`
     dicts, you can point it at any source that yields those fields without
     touching `briefing.py`.
4. **Use the official Indeed Publisher API** (requires signing up for a publisher
   key) for a supported, stable feed.

### No email arrived

- Check the **Actions** run logs. A red **Send briefing** step usually means an
  SMTP auth error → re-check `EMAIL_SENDER` and that `EMAIL_PASSWORD` is the
  **App Password**, not your Google account password.
- Look in **Spam** the first time.
- `smtplib.SMTPAuthenticationError` → App Password is wrong or 2FA got disabled.

### AI summarization failed

- The logs will say so and the email is sent using a raw-data fallback layout.
- Common causes: expired/incorrect `GH_MODELS_TOKEN`, the token missing the
  **Models** permission, or hitting the free-tier rate limit. Regenerate the
  token (step 1) and update the secret.

### A news feed is missing

- Feeds occasionally change URLs or go down. The run logs
  `Error fetching feed '<name>'` and continues. Update the URL in `RSS_FEEDS` in
  `fetcher.py` if a source is permanently broken.

---

## Customizing

- **Recipient context / tone:** edit `RECIPIENT_CONTEXT` in `briefing.py`.
- **Sections & format:** edit `OUTPUT_INSTRUCTIONS` in `briefing.py`.
- **News sources:** edit `RSS_FEEDS` in `fetcher.py`.
- **CVE threshold:** change `min_cvss` in `fetch_cves()` in `fetcher.py`.
- **Email theme:** edit `EMAIL_STYLES` / `HTML_TEMPLATE` in `briefing.py`.
- **Model:** change `MODEL` in `briefing.py` to any model available on GitHub
  Models (e.g. a different Llama or GPT variant).
