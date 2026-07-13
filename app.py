"""Phish-Guard AI - Streamlit web UI (Groq backend).

A lightweight, "clone and run" web app that detects phishing / BEC / social
engineering in email using the Groq API (free, fast Llama 3 models).

Run it with:
    streamlit run app.py

Two modes:
  * Tab 1 - Live Inbox Monitor : fetch unread mail over IMAP and analyse each one.
  * Tab 2 - Manual Tester      : paste a subject + body and analyse instantly.

No API keys or credentials are ever hardcoded. They are typed into masked
password fields in the sidebar (optionally pre-filled from a local .env file).
"""

from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv

from phish_guard.config import Config
from phish_guard.email_client import EmailClient, EmailClientError
from phish_guard.groq_analyzer import (
    GroqAnalysisError,
    analyze_email,
)

# Optional: pre-fill sidebar fields from a local .env if one exists.
load_dotenv()

# Risk_Score at/above this is shown as an alert. 70 balances false positives
# (lower = more alerts, noisier) with false negatives (higher = misses attacks).
ALERT_THRESHOLD = 70

# --- Fixed, non-sensitive settings (Plug & Play: not shown in the UI) --------
# These are safe to hardcode because they are NOT secrets. The two actual
# secrets are handled securely instead:
#   * Groq API key   -> BYOK: typed into a masked sidebar field at runtime.
#   * IMAP password  -> entered in a masked sidebar field, and OPTIONALLY
#                       pre-filled from the IMAP_APP_PASSWORD environment
#                       variable (loaded from a local .env). Never hardcoded.
# Groq's fastest Llama-3.3 70B model: free tier, no credit card, strong reasoning.
GROQ_MODEL = "llama-3.3-70b-versatile"
IMAP_USERNAME = "phishguardbgu@gmail.com"
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
IMAP_MAILBOX = "INBOX"

st.set_page_config(page_title="Phish-Guard AI", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------------
# Visual theme (presentation only - no functional impact)
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
      /* Constrain and center the main content for a cleaner reading width */
      .block-container { padding-top: 2.2rem; max-width: 1180px; }

      /* Buttons: rounded, with a subtle hover lift */
      .stButton > button {
        border-radius: 10px;
        font-weight: 600;
        transition: transform .06s ease, box-shadow .15s ease, filter .15s ease;
      }
      .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 18px rgba(0,0,0,.18);
        filter: brightness(1.03);
      }
      .stButton > button:active { transform: translateY(0); }

      /* Primary button: brand gradient with high-contrast label */
      .stButton > button[kind="primary"],
      .stButton > button[data-testid="baseButton-primary"] {
        background: linear-gradient(135deg, #4c6ef5 0%, #7048e8 100%);
        border: none;
        color: #ffffff !important;
        font-weight: 700;
        text-shadow: 0 1px 2px rgba(0,0,0,.30);
      }
      .stButton > button[kind="primary"] p,
      .stButton > button[data-testid="baseButton-primary"] p { color: #ffffff !important; }

      /* Tabs: roomier, pill-like headers */
      .stTabs [data-baseweb="tab-list"] { gap: 8px; }
      .stTabs [data-baseweb="tab"] {
        border-radius: 10px 10px 0 0;
        padding: 8px 18px;
        font-weight: 600;
      }

      /* Inputs: softly rounded */
      .stTextInput input, .stTextArea textarea, .stNumberInput input {
        border-radius: 10px !important;
      }

      /* Alerts and expanders: rounded cards */
      [data-testid="stAlert"] { border-radius: 12px; }
      [data-testid="stExpander"] { border-radius: 12px; overflow: hidden; }

      /* Metric: subtle card */
      [data-testid="stMetric"] {
        background: rgba(128,128,128,.06);
        border: 1px solid rgba(128,128,128,.16);
        border-radius: 12px;
        padding: 12px 16px;
      }

      /* Sidebar labels: a touch bolder */
      [data-testid="stSidebar"] label { font-weight: 600; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------
def risk_color(score: int) -> str:
    if score >= ALERT_THRESHOLD:
        return "#e03131"  # red
    if score >= ALERT_THRESHOLD // 2:
        return "#f08c00"  # orange
    return "#2f9e44"  # green


def render_result(sender: str, subject: str, body: str, verdict: dict) -> None:
    score = verdict["Risk_Score"]
    color = risk_color(score)
    label = "⚠️ PHISHING / SUSPICIOUS" if score >= ALERT_THRESHOLD else "✅ LIKELY SAFE"

    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(
            f"""
            <div style="text-align:center;padding:18px 12px;border-radius:16px;
                        border:1px solid {color}40;
                        background:linear-gradient(160deg,{color}1f,{color}08);
                        box-shadow:0 6px 20px {color}26;">
              <div style="font-size:52px;font-weight:800;line-height:1;color:{color};
                          text-shadow:0 2px 12px {color}55;">{score}</div>
              <div style="color:#868e96;font-size:12px;letter-spacing:1px;margin-top:6px;">
                RISK SCORE / 100</div>
              <div style="margin-top:12px;font-weight:700;font-size:14px;color:{color};">{label}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.progress(score / 100)
        st.markdown("**Explainable AI (XAI) - why it was flagged:**")
        st.write(verdict["XAI_Explanation"])

    with st.expander("View original email"):
        if sender:
            st.text(f"From:    {sender}")
        st.markdown("**Subject:**")
        st.text(subject or "(no subject)")
        st.markdown("**Body:**")
        st.text(body or "(empty body)")


# ---------------------------------------------------------------------------
# Sidebar - secure configuration (nothing hardcoded)
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ Phish-Guard AI")
st.sidebar.caption("Enter your credentials to begin.")

# BYOK (Bring Your Own Key): the Groq API key is provided by the user at runtime
# via a masked field. It is never hardcoded or committed.
groq_api_key = st.sidebar.text_input(
    "Groq API Key",
    value=os.getenv("GROQ_API_KEY", ""),
    type="password",
    help="Free key from console.groq.com/keys",
)

# IMAP app password: entered in a masked field. If an IMAP_APP_PASSWORD env var
# is present (from a local .env) it pre-fills the field for convenience, but the
# password is never hardcoded and never committed. Live Inbox Monitor only.
imap_password = st.sidebar.text_input(
    "IMAP App Password",
    value=os.getenv("IMAP_APP_PASSWORD", ""),
    type="password",
    help=f"16-char Gmail app password for {IMAP_USERNAME} (Live Inbox Monitor only).",
)

# Fixed settings resolved from constants (not user-editable).
model = GROQ_MODEL
imap_username = IMAP_USERNAME
imap_host = IMAP_HOST
imap_port = IMAP_PORT
imap_mailbox = IMAP_MAILBOX

groq_ready = bool(groq_api_key)
imap_ready = bool(imap_password)
if not groq_ready:
    st.sidebar.warning("Enter your Groq API key to enable analysis.")


# ---------------------------------------------------------------------------
# Main area
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div style="padding:22px 26px;border-radius:18px;margin-bottom:14px;
                background:linear-gradient(120deg,#4c6ef5 0%,#7048e8 55%,#9c36b5 100%);
                box-shadow:0 10px 30px rgba(80,72,229,.35);">
      <div style="display:flex;align-items:center;gap:14px;">
        <div style="font-size:40px;line-height:1;">🛡️</div>
        <div>
          <div style="font-size:30px;font-weight:800;color:#ffffff;letter-spacing:.3px;">
            Phish-Guard AI</div>
          <div style="color:#e9ecff;font-size:14px;margin-top:3px;">
            Semantic detection of phishing, BEC &amp; social-engineering attacks
            &nbsp;·&nbsp; powered by Groq LLM</div>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Decorative capability chips + risk-scale legend (presentation only).
st.markdown(
    """
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin:2px 0 14px 0;">
      <div style="flex:1;min-width:170px;padding:14px 16px;border-radius:14px;
                  background:rgba(76,110,245,.10);border:1px solid rgba(76,110,245,.28);">
        <div style="font-size:22px;">🧠</div>
        <div style="font-weight:700;margin-top:4px;">Intent-based</div>
        <div style="font-size:12px;color:#868e96;">Reads meaning, not keywords</div>
      </div>
      <div style="flex:1;min-width:170px;padding:14px 16px;border-radius:14px;
                  background:rgba(112,72,232,.10);border:1px solid rgba(112,72,232,.28);">
        <div style="font-size:22px;">🔍</div>
        <div style="font-weight:700;margin-top:4px;">Explainable (XAI)</div>
        <div style="font-size:12px;color:#868e96;">Names every red flag</div>
      </div>
      <div style="flex:1;min-width:170px;padding:14px 16px;border-radius:14px;
                  background:rgba(156,54,181,.10);border:1px solid rgba(156,54,181,.28);">
        <div style="font-size:22px;">⚡</div>
        <div style="font-weight:700;margin-top:4px;">Groq-powered</div>
        <div style="font-size:12px;color:#868e96;">Fast Llama-3.3 analysis</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;
                margin:0 0 8px 2px;font-size:12px;color:#868e96;">
      <span style="font-weight:700;">Risk scale:</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
            background:#2f9e44;margin-right:6px;vertical-align:middle;"></span>1–34 Safe</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
            background:#f08c00;margin-right:6px;vertical-align:middle;"></span>35–69 Suspicious</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
            background:#e03131;margin-right:6px;vertical-align:middle;"></span>70–100 Phishing</span>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_live, tab_manual = st.tabs(["📥 Live Inbox Monitor", "🧪 Manual Tester"])

# --- Tab 1: Live Inbox Monitor -------------------------------------------------
with tab_live:
    st.subheader("📥 Fetch and analyse unread emails")

    st.info(
        f"🧩 **This tab is a demo bound to one shared inbox** (`{IMAP_USERNAME}`). "
        "In production the same engine works on **any** IMAP mailbox — only the "
        "hardcoded connection settings would change.\n\n"
        f"**To try it live:** send a test email (e.g. a phishing sample) to "
        f"**{IMAP_USERNAME}**, then click **Fetch & Analyze unread** below to scan it."
    )

    limit = st.number_input("Max emails to analyse", min_value=1, max_value=50, value=5, step=1)
    fetch_clicked = st.button(
        "Fetch & Analyze unread",
        type="primary",
        disabled=not (groq_ready and imap_ready),
        help="Requires both the Groq API Key and the IMAP App Password in the sidebar.",
    )
    if not (groq_ready and imap_ready):
        missing = []
        if not groq_ready:
            missing.append("**Groq API Key**")
        if not imap_ready:
            missing.append("**IMAP App Password**")
        st.warning(
            "🔒 **Fetch & Analyze unread** is disabled until you enter "
            + " and ".join(missing)
            + f" in the sidebar (the IMAP password is the 16-char Gmail app "
            f"password for {IMAP_USERNAME})."
        )

    if fetch_clicked:
        # Build a Config purely from the sidebar values. The web UI analyses via
        # Groq (analyze_email). IMAP creds never leave this in-memory object.
        config = Config(
            imap_host=imap_host,
            imap_port=int(imap_port),
            imap_username=imap_username,
            imap_password=imap_password,
            imap_mailbox=imap_mailbox,
            imap_use_ssl=True,       # Always connect over TLS (IMAP4_SSL, port 993).
            mark_as_read=False,      # Read-only: never flag the user's real mail.
            poll_interval=60,
            risk_threshold=ALERT_THRESHOLD,
            log_file="phish_guard.log",
        )
        # EmailClient opens an IMAP4_SSL socket, logs in, selects the mailbox and
        # fetches UNSEEN mail. A wrong password or network failure is raised as
        # EmailClientError; any other unexpected fault is caught so the UI never
        # hard-crashes and always shows a readable message instead.
        try:
            with st.spinner("Connecting to inbox..."):
                with EmailClient(config) as client:
                    messages = client.fetch_unread()
        except EmailClientError as exc:
            st.error(f"IMAP error: {exc}")
            messages = []
            fetch_failed = True
        except Exception as exc:  # pragma: no cover - last-resort UI safety net
            st.error(f"Unexpected error while fetching mail: {exc}")
            messages = []
            fetch_failed = True
        else:
            fetch_failed = False

        messages = messages[: int(limit)]
        if not messages:
            # Only say "no messages" on a successful fetch; on error the
            # st.error above already explains what went wrong.
            if not fetch_failed:
                st.info("No unread messages found.")
        else:
            st.success(f"Analysing {len(messages)} unread message(s)...")
            alerts = 0
            for msg in messages:
                st.divider()
                with st.spinner(f"Analysing: {msg.subject or '(no subject)'}"):
                    # One Groq call per email. GroqAnalysisError wraps API
                    # timeouts, rate limits and unparseable output, so a single
                    # bad message is skipped rather than aborting the whole scan.
                    try:
                        verdict = analyze_email(groq_api_key, model, msg.subject, msg.body)
                    except GroqAnalysisError as exc:
                        st.warning(f"Skipped '{msg.subject}': {exc}")
                        continue
                if verdict["Risk_Score"] >= ALERT_THRESHOLD:
                    alerts += 1
                render_result(msg.sender, msg.subject, msg.body, verdict)
            st.divider()
            st.metric("Alerts found", alerts)

# --- Tab 2: Manual Tester ------------------------------------------------------
with tab_manual:
    st.subheader("🧪 Analyse a single email")

    st.info(
        "🧪 **Paste any email here to test the detector instantly** — no inbox or "
        "IMAP password needed, just the **Groq API Key** in the sidebar.\n\n"
        "**To try it:** drop in a subject and body (or use a demo sample from the "
        "README), then click **Analyze** to get a Risk Score and explanation."
    )

    subject = st.text_input("Email Subject", placeholder="e.g. Urgent: verify your account now")
    body = st.text_area(
        "Email Body",
        height=200,
        placeholder=(
            "e.g. Your account will be suspended within 24 hours unless you "
            "verify your password immediately at http://secure-verify-login.com"
        ),
    )
    analyze_clicked = st.button(
        "Analyze",
        type="primary",
        disabled=not groq_ready,
        help="Requires your Groq API Key in the sidebar.",
    )
    if not groq_ready:
        st.warning(
            "🔒 **Analyze** is disabled until you enter your **Groq API Key** "
            "in the sidebar."
        )

    if analyze_clicked:
        # Guard empty input: don't waste an API call on a blank email.
        if not subject.strip() and not body.strip():
            st.warning("Enter a subject or a body to analyse.")
        else:
            with st.spinner("Analysing with Groq..."):
                # Single Groq call; GroqAnalysisError surfaces API/parse issues.
                try:
                    verdict = analyze_email(groq_api_key, model, subject, body)
                except GroqAnalysisError as exc:
                    st.error(str(exc))
                    st.info("Check that your Groq API key in the sidebar is valid.")
                else:
                    render_result("", subject, body, verdict)
