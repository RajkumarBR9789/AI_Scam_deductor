"""
Forgot Password page for ScamShield frontend.
Three-step flow: email → OTP → new password.
"""

import html
import re

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
        .stApp, section.main, [data-testid="stAppViewContainer"],
        [data-testid="stBottomBlockContainer"] { background: #000 !important; }
        [data-testid="stHeader"] { display: none !important; }
        footer { display: none !important; }
        html, body, * { font-family: 'Courier New', Courier, monospace !important; }
        .block-container { max-width: 440px !important; padding: 56px 0 48px !important; margin: 0 auto !important; }
        [data-testid="stTextInput"] label p { color: #555 !important; font-size: 10px !important; letter-spacing: 2px !important; text-transform: uppercase !important; }
        [data-testid="stTextInput"] > div > div { background: #0A0A0A !important; border: 1px solid #1E1E1E !important; border-radius: 0 !important; box-shadow: none !important; }
        [data-testid="stTextInput"] > div > div:focus-within { border-color: #FFF !important; }
        [data-testid="stTextInput"] input { background: transparent !important; color: #FFF !important; font-size: 15px !important; caret-color: #FFF !important; border-radius: 0 !important; }
        [data-testid="stTextInput"] input::placeholder { color: #2E2E2E !important; }
        [data-testid="stTextInput"] input:focus { box-shadow: none !important; }
        .stButton > button { width: 100% !important; border-radius: 0 !important; font-family: 'Courier New', monospace !important; font-weight: 900 !important; font-size: 11px !important; letter-spacing: 3px !important; text-transform: uppercase !important; padding: 16px 0 !important; line-height: 1 !important; border: none !important; background: #FFF !important; color: #000 !important; transition: opacity 0.15s !important; }
        .stButton > button:hover { opacity: 0.8 !important; background: #FFF !important; }
        .stButton > button:focus { box-shadow: none !important; outline: none !important; }
        .ghost-before + div .stButton > button { background: transparent !important; color: #3A3A3A !important; border: 1px solid #1A1A1A !important; font-size: 10px !important; letter-spacing: 2px !important; }
        .ghost-before + div .stButton > button:hover { border-color: #444 !important; color: #666 !important; opacity: 1 !important; }

        /* ── Responsive / Mobile ── */
        @media (max-width: 768px) {
            .block-container { max-width: 100% !important; padding: 36px 20px 40px !important; }
        }
        @media (max-width: 480px) {
            .block-container { padding: 24px 14px 32px !important; }
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


def _header(subtitle: str) -> None:
    _step = st.session_state.get("fp_step", 1)
    _dots = "".join(
        f"<span style='display:inline-block;width:8px;height:8px;border-radius:50%;"
        f"background:{'#FFF' if i == _step else '#2A2A2A'};margin:0 5px'></span>"
        for i in range(1, 4)
    )
    st.markdown(
        f"""
        <div style="text-align:center;padding:0 0 40px">
            <div style="color:#222;font-size:10px;letter-spacing:4px;
                        text-transform:uppercase;margin-bottom:16px">Scam Shield</div>
            <div style="font-size:48px;line-height:1">&#9889;</div>
            <div style="margin:16px auto 0;width:32px;height:2px;background:#FFF"></div>
        </div>
        <div style="text-align:center;margin-bottom:8px">{_dots}</div>
        <div style="color:#2A2A2A;font-size:9px;letter-spacing:3px;text-transform:uppercase;
                    text-align:center;margin-bottom:12px">Step {_step} of 3</div>
        <div style="color:#FFF;font-size:20px;font-weight:900;letter-spacing:5px;
                    text-transform:uppercase;text-align:center;margin-bottom:8px">
            Reset Password
        </div>
        <p style="color:#444;font-size:11px;letter-spacing:1px;text-align:center;
                  margin-bottom:36px">{subtitle}</p>
        """,
        unsafe_allow_html=True,
    )


# ────────────────────────── Step 1: Enter Email ──────────────────────────
def _step_email() -> None:
    _header("Enter your email to receive a reset code.")

    msg = st.empty()

    with st.form("fp_email_form"):
        st.text_input("Email Address", placeholder="you@example.com", key="fp_email_input")
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _submitted = st.form_submit_button("Send Reset Code", use_container_width=True)

    if _submitted:
        email = st.session_state.get("fp_email_input", "").strip()
        if not email:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Email address is required.</p>", unsafe_allow_html=True)
        elif not _is_valid_email(email):
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Enter a valid email address.</p>", unsafe_allow_html=True)
        else:
            with st.spinner("Sending…"):
                result = _api.forgot_password(email)
            if result["success"]:
                st.session_state["fp_email"] = email
                st.session_state["fp_step"] = 2
                st.rerun()
            else:
                err = result["error"] or "Failed to send reset code."
                msg.markdown(
                    f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    f"&#9888; {err}</p>", unsafe_allow_html=True)

    _back_to_signin()


# ────────────────────────── Step 2: Enter OTP ──────────────────────────
def _step_otp() -> None:
    email = st.session_state.get("fp_email", "")
    _header(f"Enter the 6-digit code sent to <span style='color:#888'>{html.escape(email)}</span>")

    msg = st.empty()

    with st.form("fp_otp_form"):
        st.text_input("6-Digit Code", placeholder="000000", max_chars=6, key="fp_otp_input")
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _submitted = st.form_submit_button("Verify Code", use_container_width=True)

    if _submitted:
        code = st.session_state.get("fp_otp_input", "").strip()
        if not code or not code.isdigit() or len(code) != 6:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Enter the 6-digit numeric code.</p>", unsafe_allow_html=True)
        else:
            with st.spinner("Verifying…"):
                result = _api.verify_reset_token(email, code)
            if result["success"]:
                st.session_state["fp_reset_token"] = code
                st.session_state["fp_step"] = 3
                st.rerun()
            else:
                err = result["error"] or "Invalid or expired code."
                msg.markdown(
                    f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    f"&#9888; {err}</p>", unsafe_allow_html=True)

    _back_to_signin()


# ────────────────────────── Step 3: New Password ──────────────────────────
def _step_new_password() -> None:
    _header("Choose a new password.")

    msg = st.empty()

    with st.form("fp_new_pw_form"):
        st.text_input("New Password", type="password", placeholder="Min. 8 characters",
                      key="fp_new_password_input")
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        st.text_input("Confirm Password", type="password", placeholder="Re-enter password",
                      key="fp_confirm_password_input")
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _submitted = st.form_submit_button("Reset Password", use_container_width=True)

    if _submitted:
        pw   = st.session_state.get("fp_new_password_input", "")
        cpw  = st.session_state.get("fp_confirm_password_input", "")
        if len(pw) < 8:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Password must be at least 8 characters.</p>", unsafe_allow_html=True)
        elif pw != cpw:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Passwords do not match.</p>", unsafe_allow_html=True)
        else:
            email = st.session_state.get("fp_email", "")
            token = st.session_state.get("fp_reset_token", "")
            with st.spinner("Resetting…"):
                result = _api.reset_password(email, token, pw)
            if result["success"]:
                # Clean up forgot-password state
                for k in ("fp_step", "fp_email", "fp_reset_token"):
                    st.session_state.pop(k, None)
                msg.markdown(
                    "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    "&#10003; Password reset! Redirecting to sign in&hellip;</p>",
                    unsafe_allow_html=True,
                )
                st.session_state["page"] = "signin"
                st.rerun()
            else:
                err = result["error"] or "Reset failed."
                msg.markdown(
                    f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    f"&#9888; {err}</p>", unsafe_allow_html=True)

    _back_to_signin()


# ────────────────────────── Shared ──────────────────────────
def _back_to_signin() -> None:
    st.markdown("<div style='margin:32px 0;border-top:1px solid #111'></div>", unsafe_allow_html=True)
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("\u2190 Back to Sign In", use_container_width=True, key="fp_back_btn"):
        for k in ("fp_step", "fp_email", "fp_reset_token"):
            st.session_state.pop(k, None)
        st.session_state["page"] = "signin"
        st.rerun()


def render_forgot_password_page() -> None:
    _css()
    step = st.session_state.get("fp_step", 1)
    if step == 1:
        _step_email()
    elif step == 2:
        _step_otp()
    elif step == 3:
        _step_new_password()
