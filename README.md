# Phish-Guard AI

An active-defense security agent that detects **phishing**, **Business Email
Compromise (BEC)** and **social-engineering** attacks by performing *semantic*
(intent-based) analysis of incoming email with a Large Language Model.

Instead of matching signatures or blocklists, Phish-Guard reads each email the
way a human analyst would and asks: *what is the sender trying to make me feel
and do?* It returns a numeric **risk score (1-100)** plus an **Explainable-AI
(XAI) explanation** naming the exact psychological triggers and red flags.

### Why semantic (LLM) analysis beats keyword filtering
Traditional filters match keywords, sender blocklists and URL signatures. Attackers
trivially bypass them by rewording, using brand-new look-alike domains, or sending
**text-only BEC** with no links at all. Phish-Guard instead judges **intent**:

- **Catches link-less attacks** — CEO/BEC wire-fraud that contains no URL or
  attachment (invisible to signature filters) is flagged on its social-engineering
  intent alone.
- **Resists evasion** — paraphrasing or novel domains don't help, because the model
  reasons about meaning, not exact strings.
- **Explainable** — every verdict names the specific manipulation tactics (urgency,
  authority, secrecy), so a human can trust and audit it — not a black-box score.

---

## 🚀 Quick Start — Web App (Zero to Hero)

This is the fastest way to run Phish-Guard. You need **one** free account (Groq);
everything else is pre-configured.

### Step 0 — Prerequisites
- **Python 3.10 or newer** on your PATH — check with `python --version`.
- **Git** (or just download the repo as a ZIP).
- A web browser.

### Step 1 — Get the code
```bash
git clone <repo-url>
cd <project-folder>
```
*(Or download the ZIP from the repo page, unzip it, and `cd` into the folder.)*

### Step 2 — Install
Create an isolated environment and install the dependencies:

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> The rest of this guide shows the Windows form `.\.venv\Scripts\python.exe ...`.
> On macOS/Linux, activate the venv (`source .venv/bin/activate`) once and then
> just use `python`/`streamlit` directly (drop the `.\.venv\Scripts\` prefix).

### Step 3 — Get your key(s)
Phish-Guard needs **at most two secrets**. You type them into the app's sidebar —
they are **never** written to the code or committed to the repo.

#### 🔑 A. Groq API Key — *required* (powers the AI analysis)
The "brain" is a Large Language Model hosted by **Groq** (free, no credit card).
1. Go to **<https://console.groq.com/keys>**.
2. Sign in with Google or GitHub — it's free.
3. Click **Create API Key**, name it anything, and **copy** the key (it looks
   like `gsk_...`). Save it now — Groq only shows it once.

This key alone is enough to use the **Manual Tester** tab.

#### 📧 B. IMAP App Password — *optional* (only for the Live Inbox Monitor)
The **Live Inbox Monitor** logs into a real mailbox over IMAP and scans unread
mail. The app is **hard-wired to a shared demo test inbox** (you do not
type any of this — it's baked into the code):

> **Sandbox inbox:** `phishguardbgu@gmail.com` &nbsp;·&nbsp; host `imap.gmail.com`
> &nbsp;·&nbsp; port `993` &nbsp;·&nbsp; mailbox `INBOX`

To connect you need that inbox's **Gmail App Password** — a 16-character code,
**not** the normal account password (Gmail requires this for IMAP). You type it
into the masked **IMAP App Password** field in the sidebar; it lives only in
memory for that session and is never written to disk or committed.

**How to receive this password securely** (it belongs to a shared account, so it
is sent to you, not self-generated):
1. The owner sends it via a **one-time secret link** (e.g.
   [onetimesecret.com](https://onetimesecret.com) or a password-manager share) —
   **never** by email, chat, or inside this repo.
2. Open the link, **copy** the 16-character code, and keep it somewhere safe
   (a password manager) — one-time links self-destruct after viewing, so you
   cannot re-open them.
3. Paste it into the sidebar's **IMAP App Password** field when you run the app.

> ⚠️ **Keep the copied password written down** (in your password manager). The
> one-time link can be viewed **only once** — if you lose it before saving, the
> owner must generate and resend a new one.
>
> *(Optional convenience:* you may instead put `IMAP_APP_PASSWORD=...` in a local
> `.env` file to pre-fill the sidebar field automatically — see
> [.env.example](.env.example). The `.env` file is git-ignored.)*

> You only need this to demo the live inbox. The **Manual Tester** works with the
> Groq key alone.

### Step 4 — Run the app
```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```
> **First launch only:** Streamlit prints a one-time welcome banner asking for an
> email. Just press **Enter** to skip it. The app then opens at
> **<http://localhost:8501>** (if the browser doesn't open, paste that URL in).

### Step 5 — Use it
In the **sidebar**, paste your **Groq API Key** (required). For the live monitor,
also paste the **IMAP App Password** you received. Then choose a tab:

- **🧪 Manual Tester** — paste any email subject + body, click **Analyze**, and
  instantly get a **Risk Score (1-100)** plus an **Explainable-AI** breakdown of
  the exact red flags. *No mailbox needed — best for a quick demo.*
- **📥 Live Inbox Monitor** — click **Fetch & Analyze unread** to pull unread
  mail from the sandbox inbox and score every message. *(Needs the IMAP App
  Password in the sidebar.)*

  > **This tab is a demo bound to one shared inbox** (`phishguardbgu@gmail.com`).
  > The detection engine works on **any** IMAP mailbox in production — only the
  > hardcoded connection settings would change. **To try it live:** send a test
  > email (e.g. one of the phishing samples below) to `phishguardbgu@gmail.com`,
  > then click **Fetch & Analyze unread** to scan it.

That's it — you're live. 🎉

---

## Credentials at a glance

| Secret | Required? | What it is | Where to get it | How it's provided |
|--------|-----------|------------|-----------------|-------------------|
| **Groq API Key** | ✅ Yes | Auth token for the Groq LLM that scores emails | <https://console.groq.com/keys> | **BYOK** — typed into the masked sidebar field at runtime |
| **IMAP App Password** | ⬜ Optional | 16-char Gmail app password for the sandbox inbox `phishguardbgu@gmail.com` | Sent to you via a **one-time secret link** | Typed into the masked sidebar field (may be pre-filled from a local `.env`) |

> **Security model (secret handling):**
> - **BYOK (Bring Your Own Key)** — the app never ships a Groq key; each user
>   supplies their own at runtime, so no shared credential can leak from the repo.
> - **Masked, in-memory secrets** — both secrets are entered in `type="password"`
>   fields and held only in memory for the session; nothing is written to disk.
> - **Secure transport** — the shared IMAP password is delivered by a one-time,
>   self-destructing link, never by email/chat/repo.
> - **`.gitignore`** excludes `.env`, so **no secret can ever be committed**.
>   Only non-secret settings (sandbox email, host/port/mailbox, model) live in code.

---

## Under the hood: which LLM does it use?

The **web app** (`app.py`) sends each email to **Groq** using the
`llama-3.3-70b-versatile` model via the official `groq` Python client. Groq's free
tier is fast and needs no credit card — that's why the app asks each user for
their own key instead of shipping one.

---

## How the risk score & alert decision work

**1. The score (`Risk_Score`, 1–100) is produced by the LLM — not by counting
keywords.** The system prompt gives the model an explicit rubric and asks it to
place each email on this scale based on *intent*:

| Band | Meaning |
|------|---------|
| **1–20**   | Benign / legitimate business or personal mail |
| **21–50**  | Mildly suspicious — some marketing pressure, but no clear attack |
| **51–75**  | Likely phishing or social engineering — multiple red flags |
| **76–100** | High-confidence phishing / BEC — clear malicious intent |

Every score comes with an `XAI_Explanation` that names the specific triggers it
found (urgency, authority, secrecy, credential/wire requests, look-alike
domains…), so the number is auditable rather than a black box. The parser then
**clamps** the value into the 1–100 range for safety.

**2. The yes/no alert decision is a single threshold.** An email is flagged as an
**ALERT** when its score is **at or above the alert threshold** (default **70**):

- **Web app** — a score **≥ 70** is shown as **⚠️ PHISHING / SUSPICIOUS**; below
  70 it shows **✅ LIKELY SAFE**. The cutoff is `ALERT_THRESHOLD` in
  [`app.py`](app.py). The Live Inbox Monitor also tallies how many scanned
  messages crossed it ("Alerts found").

**3. Colour bands are for display only** and do **not** change the alert
decision: 🟢 **1–34** safe · 🟠 **35–69** suspicious · 🔴 **70–100** phishing.

> **Why a threshold instead of trusting the raw number?** The LLM gives a nuanced
> 1–100 score, but a defense tool ultimately needs a binary *act / don't act*
> decision. The threshold makes that boundary explicit and tunable: lower it to
> catch more (more false positives), raise it to alert only on the clearest
> attacks (more false negatives).

---

## For reviewers / graders

You do **not** need any credential from the author to evaluate the AI detection.
To run this project in under a minute:

1. Get your **own free Groq API key** (no credit card, ~30 seconds):
   - Open **<https://console.groq.com/keys>** and sign in with Google or GitHub.
   - Click **Create API Key**, name it anything, and **copy** it (`gsk_...`).
2. Launch the app: `.\.venv\Scripts\python.exe -m streamlit run app.py`
3. Paste the key into the **Groq API Key** field in the sidebar.
4. Open the **🧪 Manual Tester** tab and paste one of the demo emails below.

That's all that's required to evaluate the AI detection.

### Optional: running the Live Inbox Monitor
This tab is a **demo bound to one shared inbox** (`phishguardbgu@gmail.com`) — the
same engine works on **any** IMAP mailbox in production; only the hardcoded
connection settings would change. Because it logs into that shared account, it
needs the account's **Gmail App Password**, which the author sends you securely:

1. The author shares the 16-character password via a **one-time secret link**
   (e.g. [onetimesecret.com](https://onetimesecret.com)) — **not** by email/chat.
2. Open the link and **copy the code immediately** — the link self-destructs
   after one view, so **save it in your password manager right away**. ⚠️
3. In the app sidebar, paste it into the **IMAP App Password** field.
4. **Send a test email** (e.g. one of the demo phishing samples below) to
   `phishguardbgu@gmail.com`, then click **Fetch & Analyze unread** to scan it.

> The password is entered in a masked field and kept only in memory for the
> session — it is never written to the repo. *(You may optionally place it in a
> local `.env` as `IMAP_APP_PASSWORD=...` to pre-fill the field; `.env` is
> git-ignored.)* After grading, the author revokes the app password.

---

## Demo test cases (copy-paste into the Manual Tester)

Paste each **Subject** and **Body** into the **🧪 Manual Tester** tab and click
**Analyze**. Expected behaviour is noted for each.

### 1. High-Risk Phishing (credential harvesting) — expect a **high** score
**Subject:**
```
Urgent: Your Microsoft 365 password expires today
```
**Body:**
```
Dear user,

Our records show your Microsoft 365 password will expire in the next 2 hours.
To avoid losing access to your email and files, you must verify your account
immediately.

Click here to keep your current password:
http://microsoft365-secure-verify.com/login

Failure to act now will result in permanent account suspension.

IT Support Team
```

### 2. Sophisticated BEC / CEO fraud (no links, pure social engineering) — expect a **high** score
**Subject:**
```
Quick favor - are you at your desk?
```
**Body:**
```
Hi,

I'm heading into back-to-back meetings and can't take calls for the next hour.
I need you to handle a confidential vendor payment before end of day - we're
finalizing an acquisition and it has to stay between us for now.

Please let me know the fastest way you can process an international wire, and
I'll send the beneficiary details right away. Keep this discreet until I
announce it.

Thanks,
David
CEO
```

### 3. Low-Risk Safe email (legitimate business) — expect a **low** score
**Subject:**
```
Team lunch moved to Thursday
```
**Body:**
```
Hi everyone,

Just a heads-up that our monthly team lunch is moving from Wednesday to this
Thursday at 12:30 in the usual place downstairs. No need to bring anything -
it's already booked under the team account.

Let me know if you have any dietary preferences and I'll pass them along.

Cheers,
Maria
```

---

## Project layout

```
phish-guard-ai/
├── phish_guard/
│   ├── __init__.py
│   ├── config.py         # env-var configuration (Config)
│   ├── models.py         # EmailMessage dataclass
│   ├── email_client.py   # IMAP: fetch unread, extract sender/subject/body
│   └── groq_analyzer.py  # Groq API analysis (Risk_Score/XAI_Explanation)
├── tests/                # unit tests
├── app.py                # Streamlit web UI (Groq backend, 2 modes)
├── requirements.txt
├── .env.example          # copy to .env and fill in
├── LICENSE               # MIT license
└── pytest.ini
```

---

## Web app — how it works

*(How to run it is covered in the [Quick Start](#-quick-start--web-app-zero-to-hero) above.)*

The Streamlit UI ([`app.py`](app.py)) has three parts:

1. **Sidebar — secure configuration.** Exactly **two** masked password fields:
   your **Groq API Key** and the **IMAP App Password**. Everything else (sandbox
   email, IMAP host/port/mailbox, model) is fixed in code — a true "plug & play"
   setup. Neither secret is ever hardcoded or committed.
2. **📥 Live Inbox Monitor (Tab 1).** Connects to the sandbox inbox
   `phishguardbgu@gmail.com`, fetches unread mail, analyses each with Groq, and
   shows a feed — every entry with the original email, `Risk_Score` (1-100) and
   `XAI_Explanation`. **This is a demo bound to one shared inbox** — the engine
   works on **any** IMAP mailbox in production; only the hardcoded connection
   settings would change. To test it, send an email to that address and scan.
3. **🧪 Manual Tester (Tab 2).** Type an email subject and body, click
   **Analyze**, and instantly see the `Risk_Score` and `XAI_Explanation`.

The Groq analysis returns a strict JSON contract with exactly two keys —
`Risk_Score` (int 1-100) and `XAI_Explanation` (string). The logic lives in
[`phish_guard/groq_analyzer.py`](phish_guard/groq_analyzer.py) and is unit-tested
independently of the UI.

---

## The system prompt (semantic analysis)

[`phish_guard/groq_analyzer.py`](phish_guard/groq_analyzer.py) contains
`SYSTEM_PROMPT`, which instructs the model to act as a cybersecurity analyst and
look for:

1. **Urgency / Fear** — suspension threats, artificial deadlines, panic language.
2. **Authority / Impersonation (BEC)** — fake CEO/IT/bank, abuse of hierarchy.
3. **Contextual anomalies & manipulation** — gift-card/wire/credential requests,
   secrecy, look-alike domains, too-good-to-be-true bait.

The model must reply with strictly this JSON:

```json
{ "Risk_Score": 0, "XAI_Explanation": "why it was flagged, with the specific triggers" }
```

The parser (`parse_verdict`) is defensive: it recovers the JSON even if the model
wraps it in markdown fences or adds prose, and clamps the score to 1-100.

---

## Testing

```powershell
python -m pytest
```

- **Unit tests** — config validation, JSON parsing/clamping, IMAP body extraction
  & header decoding, and the Groq analyzer's `Risk_Score`/`XAI_Explanation`
  contract (including malformed-output and error handling).

All tests run fully offline — no email account and no LLM server required.

---

## Error handling

- **IMAP connection/login failures** raise `EmailClientError`; the UI shows a
  clear message (e.g. an invalid app password) instead of crashing.
- **A single malformed message** is skipped without aborting the whole scan.
- **Groq auth / rate-limit / network / API errors** are wrapped in
  `GroqAnalysisError` with an actionable message; the offending email is skipped
  and the rest of the scan continues.

---

## License

Released under the **MIT License** — see [LICENSE](LICENSE). You are free to use,
modify and distribute this project, provided the copyright notice is retained.
