"""
Sign In page for ScamShield frontend.
"""

import html
import re
from datetime import datetime, timezone

import streamlit as st

from utils.api_client import APIClient

_api = APIClient()
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_valid_email(v: str) -> bool:
    return bool(_EMAIL_RE.match(v))


def _css() -> None:
    st.markdown(
        """
        <style>
        /* ── Background ── */
        .stApp, section.main, [data-testid="stAppViewContainer"],
        [data-testid="stBottomBlockContainer"] {
            background: #000 !important;
        }
        [data-testid="stHeader"] { display: none !important; }
        footer { display: none !important; }
        html, body, * { font-family: 'Courier New', Courier, monospace !important; }

        /* ── Narrow the content block ── */
        .block-container {
            max-width: 440px !important;
            padding: 56px 0 48px !important;
            margin: 0 auto !important;
        }

        /* ── Input labels ── */
        [data-testid="stTextInput"] label p {
            color: #555 !important;
            font-size: 10px !important;
            letter-spacing: 2px !important;
            text-transform: uppercase !important;
        }

        /* ── Input box ── */
        [data-testid="stTextInput"] > div > div {
            background: #0A0A0A !important;
            border: 1px solid #1E1E1E !important;
            border-radius: 0 !important;
            box-shadow: none !important;
        }
        [data-testid="stTextInput"] input {
            background: transparent !important;
            color: #FFF !important;
            font-size: 15px !important;
            caret-color: #FFF !important;
            border-radius: 0 !important;
        }
        [data-testid="stTextInput"] input::placeholder { color: #2E2E2E !important; }
        [data-testid="stTextInput"] input:focus { box-shadow: none !important; }
        [data-testid="stTextInput"] > div > div:focus-within {
            border-color: #FFF !important;
        }

        /* ── Checkbox ── */
        [data-testid="stCheckbox"] label span {
            color: #555 !important;
            font-size: 11px !important;
            letter-spacing: 1px !important;
        }

        /* ── Primary button ── */
        .stButton > button {
            width: 100% !important;
            border-radius: 0 !important;
            font-family: 'Courier New', monospace !important;
            font-weight: 900 !important;
            font-size: 11px !important;
            letter-spacing: 3px !important;
            text-transform: uppercase !important;
            padding: 16px 0 !important;
            line-height: 1 !important;
            border: none !important;
            background: #FFF !important;
            color: #000 !important;
            transition: opacity 0.15s !important;
            cursor: pointer !important;
        }
        .stButton > button:hover { opacity: 0.8 !important; background: #FFF !important; }
        .stButton > button:focus { box-shadow: none !important; outline: none !important; }

        /* ── Ghost button (via .ghost-before marker) ── */
        .ghost-before + div .stButton > button {
            background: transparent !important;
            color: #3A3A3A !important;
            border: 1px solid #1A1A1A !important;
            font-size: 10px !important;
            letter-spacing: 2px !important;
        }
        .ghost-before + div .stButton > button:hover {
            border-color: #444 !important;
            color: #666 !important;
            opacity: 1 !important;
        }

        /* ── Responsive / Mobile ── */
        @media (max-width: 768px) {
            .block-container {
                max-width: 100% !important;
                padding: 36px 20px 40px !important;
            }
        }
        @media (max-width: 480px) {
            .block-container {
                padding: 24px 14px 32px !important;
            }
        }

        /* ── Form (Enter to submit) ── */
        [data-testid="stForm"] { border: none !important; padding: 0 !important; background: transparent !important; box-shadow: none !important; }
        .stFormSubmitButton > button { width: 100% !important; border-radius: 0 !important; font-family: 'Courier New', monospace !important; font-weight: 900 !important; font-size: 11px !important; letter-spacing: 3px !important; text-transform: uppercase !important; padding: 16px 0 !important; line-height: 1 !important; border: none !important; background: #FFF !important; color: #000 !important; transition: opacity 0.15s !important; cursor: pointer !important; }
        .stFormSubmitButton > button:hover { opacity: 0.8 !important; background: #FFF !important; }
        .stFormSubmitButton > button:focus { box-shadow: none !important; outline: none !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_signin_page() -> None:
    _css()

    # ── Logo / Header ──
    st.markdown(
        """
        <div style="text-align:center;padding:0 0 48px">
            <div style="color:#222;font-size:10px;letter-spacing:4px;
                        text-transform:uppercase;margin-bottom:16px">Scam Shield</div>
            <div style="font-size:48px;line-height:1">&#9889;</div>
            <div style="margin:16px auto 0;width:32px;height:2px;background:#FFF"></div>
        </div>
        <div style="color:#FFF;font-size:20px;font-weight:900;letter-spacing:5px;
                    text-transform:uppercase;text-align:center;margin-bottom:36px">
            Sign In
        </div>
        """,
        unsafe_allow_html=True,
    )

    msg = st.empty()

    # ── Form: inputs + submit (Enter key submits) ──
    with st.form("signin_form"):
        st.text_input("Email Address", placeholder="you@example.com", key="signin_email_input")
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        st.text_input("Password", type="password", placeholder="••••••••", key="signin_password_input")
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        col_rem, _ = st.columns([1, 1])
        with col_rem:
            st.checkbox("Remember me", key="signin_remember_me", value=False)
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _submitted = st.form_submit_button("Sign In", use_container_width=True)

    # ── Forgot Password (outside form — navigation only) ──
    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("Forgot password?", key="goto_forgot_pw_btn", use_container_width=True):
        st.session_state["page"] = "forgot_password"
        st.rerun()

    # ── Sign In logic ──
    if _submitted:
        email_val = st.session_state.get("signin_email_input", "").strip()
        pass_val  = st.session_state.get("signin_password_input", "")
        remember  = st.session_state.get("signin_remember_me", False)

        if not email_val:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;"
                "margin:12px 0 0'>&#9888; Email address is required.</p>",
                unsafe_allow_html=True,
            )
        elif not _is_valid_email(email_val):
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;"
                "margin:12px 0 0'>&#9888; Enter a valid email address.</p>",
                unsafe_allow_html=True,
            )
        elif not pass_val:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;"
                "margin:12px 0 0'>&#9888; Password is required.</p>",
                unsafe_allow_html=True,
            )
        else:
            with st.spinner("Signing in…"):
                result = _api.login(email_val, pass_val, remember_me=remember)

            if result["success"]:
                data = result["data"]
                user = data.get("user", {})
                st.session_state["token"]          = data["access_token"]
                st.session_state["refresh_token"]  = data.get("refresh_token")
                st.session_state["user_email"]     = user.get("email", email_val)
                st.session_state["user_name"]      = user.get("name", "")
                st.session_state["plan_type"]      = user.get("plan_type", "FREE")
                st.session_state["is_pro"]         = user.get("is_pro", False)
                ts = datetime.now(timezone.utc).isoformat()
                st.session_state["session_start"]  = ts
                st.session_state["last_activity"]  = ts
                st.session_state["page"]           = "scan"
                msg.markdown(
                    "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;"
                    "margin:12px 0 0'>&#10003; Signed in. Redirecting&hellip;</p>",
                    unsafe_allow_html=True,
                )
                st.rerun()
            else:
                err = result["error"] or "Authentication failed."
                if "verify your email" in err.lower():
                    st.session_state["pending_otp_email"] = email_val
                    msg.markdown(
                        "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;"
                        "margin:12px 0 0'>&#9888; Email not verified &mdash; "
                        "check your inbox for the OTP.</p>",
                        unsafe_allow_html=True,
                    )
                    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                    if st.button("Verify Email →", use_container_width=True, key="goto_otp_signin"):
                        st.session_state["page"] = "otp_verify"
                        st.rerun()
                else:
                    msg.markdown(
                        f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;"
                        f"margin:12px 0 0'>&#9888; {html.escape(err)}</p>",
                        unsafe_allow_html=True,
                    )

    # ── Divider ──
    st.markdown(
        "<div style='margin:32px 0;border-top:1px solid #111'></div>",
        unsafe_allow_html=True,
    )

    # ── Ghost: Create Account ──
    st.markdown(
        "<p style='color:#2A2A2A;font-size:9px;letter-spacing:2px;"
        "text-transform:uppercase;text-align:center;margin:0 0 12px'>No account yet?</p>",
        unsafe_allow_html=True,
    )
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("Create Account \u2192", use_container_width=True, key="goto_signup_btn"):
        st.session_state["page"] = "signup"
        st.rerun()

    # ── Guest access ──
    st.markdown(
        "<div style='margin:16px 0;border-top:1px solid #111'></div>"
        "<p style='color:#1A1A1A;font-size:9px;letter-spacing:2px;"
        "text-transform:uppercase;text-align:center;margin:0 0 12px'>Or</p>",
        unsafe_allow_html=True,
    )
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("Try as Guest \u2192", use_container_width=True, key="goto_guest_btn"):
        st.session_state["page"] = "scan"
        st.rerun()

