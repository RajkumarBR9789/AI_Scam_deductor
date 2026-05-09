"""
Sign Up page for ScamShield frontend.
"""

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


def render_signup_page() -> None:
    _css()

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
            Create Account
        </div>
        """,
        unsafe_allow_html=True,
    )

    msg = st.empty()

    with st.form("signup_form"):
        col_fn, col_ln = st.columns(2)
        with col_fn:
            st.text_input("First Name", placeholder="John", key="signup_firstname_input")
        with col_ln:
            st.text_input("Last Name", placeholder="Doe", key="signup_lastname_input")
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        st.text_input("Email Address", placeholder="you@example.com", key="signup_email_input")
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        st.text_input("Password", type="password", placeholder="Min. 8 characters", key="signup_password_input")
        _pw_hint = st.session_state.get("signup_password_input", "")
        if _pw_hint:
            _reqs = [
                ("8+ chars", len(_pw_hint) >= 8),
                ("Uppercase", any(c.isupper() for c in _pw_hint)),
                ("Lowercase", any(c.islower() for c in _pw_hint)),
                ("Number", any(c.isdigit() for c in _pw_hint)),
            ]
            _parts = []
            for _label, _ok in _reqs:
                _color = "#00C96F" if _ok else "#333"
                _icon = "✓" if _ok else "○"
                _parts.append(
                    f"<span style='color:{_color};font-size:9px;letter-spacing:1px;"
                    f"margin-right:10px'>{_icon} {_label}</span>"
                )
            st.markdown(
                f"<div style='margin:5px 0 8px'>{''.join(_parts)}</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        st.text_input("Confirm Password", type="password", placeholder="Re-enter password", key="signup_confirm_input")
        _confirm_hint = st.session_state.get("signup_confirm_input", "")
        if _confirm_hint:
            if _confirm_hint == _pw_hint:
                st.markdown(
                    "<p style='color:#00C96F;font-size:9px;letter-spacing:1px;margin:4px 0'>✓ Passwords match</p>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<p style='color:#FF3B30;font-size:9px;letter-spacing:1px;margin:4px 0'>✗ Passwords do not match</p>",
                    unsafe_allow_html=True,
                )
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _submitted = st.form_submit_button("Create Account", use_container_width=True)

    if _submitted:
        first_val   = st.session_state.get("signup_firstname_input", "").strip()
        last_val    = st.session_state.get("signup_lastname_input", "").strip()
        email_val   = st.session_state.get("signup_email_input", "").strip()
        pass_val    = st.session_state.get("signup_password_input", "")
        confirm_val = st.session_state.get("signup_confirm_input", "")

        if not first_val or not last_val:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; First and last name are required.</p>", unsafe_allow_html=True)
        elif not email_val:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Email address is required.</p>", unsafe_allow_html=True)
        elif not _is_valid_email(email_val):
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Enter a valid email address.</p>", unsafe_allow_html=True)
        elif len(pass_val) < 8:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Password must be at least 8 characters.</p>", unsafe_allow_html=True)
        elif pass_val != confirm_val:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Passwords do not match.</p>", unsafe_allow_html=True)
        else:
            with st.spinner("Creating account…"):
                result = _api.signup(email_val, pass_val, first_val, last_val)

            if result["success"]:
                st.session_state["pending_otp_email"] = email_val
                msg.markdown(
                    "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    "&#10003; Account created! Check your email for the code.</p>",
                    unsafe_allow_html=True,
                )
                st.session_state["page"] = "otp_verify"
                st.rerun()
            else:
                err = result["error"] or "Registration failed."
                if "already registered" in err.lower():
                    msg.markdown(
                        "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        "&#9888; This email is already registered. Sign in instead.</p>",
                        unsafe_allow_html=True,
                    )
                else:
                    msg.markdown(
                        f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        f"&#9888; {err}</p>", unsafe_allow_html=True)

    st.markdown("<div style='margin:32px 0;border-top:1px solid #111'></div>", unsafe_allow_html=True)
    st.markdown(
        "<p style='color:#2A2A2A;font-size:9px;letter-spacing:2px;text-transform:uppercase;"
        "text-align:center;margin:0 0 12px'>Already have an account?</p>",
        unsafe_allow_html=True,
    )
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("Sign In \u2192", use_container_width=True, key="goto_signin_from_signup"):
        st.session_state["page"] = "signin"
        st.rerun()
 
