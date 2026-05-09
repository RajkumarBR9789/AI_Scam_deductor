"""
Sign Out page for ScamShield frontend.
"""

import html
import time
from datetime import datetime, timezone

import streamlit as st

from utils.api_client import APIClient

_api = APIClient()


def _css() -> None:
    st.markdown(
        """
        <style>
        .stApp, section.main, [data-testid="stAppViewContainer"],
        [data-testid="stBottomBlockContainer"] { background: #000 !important; }
        [data-testid="stHeader"] { display: none !important; }
        footer { display: none !important; }
        html, body, * { font-family: 'Courier New', Courier, monospace !important; }
        .block-container { max-width: 440px !important; padding: 56px 0 48px !important; margin: 0 auto !important; }

        /* Primary (Sign Out) */
        .stButton > button {
            width: 100% !important; border-radius: 0 !important;
            font-family: 'Courier New', monospace !important;
            font-weight: 900 !important; font-size: 11px !important;
            letter-spacing: 3px !important; text-transform: uppercase !important;
            padding: 16px 0 !important; line-height: 1 !important;
            border: none !important; background: #FFF !important; color: #000 !important;
            transition: opacity 0.15s !important; cursor: pointer !important;
        }
        .stButton > button:hover { opacity: 0.8 !important; background: #FFF !important; }
        .stButton > button:focus { box-shadow: none !important; outline: none !important; }

        /* Ghost (Cancel) */
        .ghost-before + div .stButton > button {
            background: transparent !important; color: #3A3A3A !important;
            border: 1px solid #1A1A1A !important; font-size: 10px !important;
            letter-spacing: 2px !important;
        }
        .ghost-before + div .stButton > button:hover {
            border-color: #444 !important; color: #666 !important; opacity: 1 !important;
        }

        /* ── Responsive / Mobile ── */
        @media (max-width: 768px) {
            .block-container { max-width: 100% !important; padding: 36px 20px 40px !important; }
        }
        @media (max-width: 480px) {
            .block-container { padding: 24px 14px 32px !important; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_signout_page() -> None:
    _css()

    if not st.session_state.get("token"):
        st.session_state["page"] = "signin"
        st.rerun()
        return

    user_email = st.session_state.get("user_email", "unknown")
    _session_duration = None
    _session_start = st.session_state.get("session_start")
    if _session_start:
        try:
            _start_dt = datetime.fromisoformat(_session_start)
            _elapsed = datetime.now(timezone.utc) - _start_dt
            _mins = int(_elapsed.total_seconds() // 60)
            if _mins < 60:
                _session_duration = f"{_mins} min{'s' if _mins != 1 else ''}"
            else:
                _session_duration = f"{_mins // 60}h {_mins % 60}m"
        except Exception:
            pass

    # ── Header ──
    st.markdown(
        """
        <div style="text-align:center;padding:0 0 48px">
            <div style="color:#222;font-size:10px;letter-spacing:4px;
                        text-transform:uppercase;margin-bottom:16px">Scam Shield</div>
            <div style="font-size:48px;line-height:1">&#9889;</div>
            <div style="margin:16px auto 0;width:32px;height:2px;background:#FFF"></div>
        </div>
        <div style="color:#FFF;font-size:20px;font-weight:900;letter-spacing:5px;
                    text-transform:uppercase;text-align:center;margin-bottom:16px">
            Sign Out
        </div>
        """,
        unsafe_allow_html=True,
    )

    _duration_html = (
        f" &mdash; <span style='color:#444'>{_session_duration}</span>"
        if _session_duration else ""
    )
    st.markdown(
        f"<p style='color:#444;font-size:11px;letter-spacing:1px;text-align:center;"
        f"margin-bottom:36px'>Signed in as "
        f"<span style='color:#888'>{html.escape(user_email)}</span>{_duration_html}</p>",
        unsafe_allow_html=True,
    )

    st.markdown(
        "<p style='color:#333;font-size:11px;letter-spacing:1px;text-align:center;"
        "margin-bottom:24px'>Your session will be ended and all unsaved data will be lost.</p>",
        unsafe_allow_html=True,
    )

    msg = st.empty()

    # ── Sign Out button ──
    if st.button("Sign Out", use_container_width=True, key="btn_signout"):
        refresh = st.session_state.get("refresh_token", "")
        with st.spinner("Signing out…"):
            _api.logout(refresh)

        for key in ("token", "refresh_token", "user_email", "user_name",
                    "plan_type", "is_pro", "session_start", "last_activity",
                    "pending_otp_email", "scan_result", "scan_history"):
            st.session_state.pop(key, None)
        st.session_state["page"] = "signin"
        msg.markdown(
            "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;"
            "margin:12px 0 0;text-align:center'>Signed out. Redirecting&hellip;</p>",
            unsafe_allow_html=True,
        )
        time.sleep(1)
        st.rerun()

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Cancel (ghost) ──
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("Cancel", use_container_width=True, key="btn_cancel"):
        st.session_state["page"] = "scan"
        st.rerun()
