"""
OTP Verification page for ScamShield frontend.
"""

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
        [data-testid="stTextInput"] label p { color: #555 !important; font-size: 10px !important; letter-spacing: 2px !important; text-transform: uppercase !important; }
        [data-testid="stTextInput"] > div > div { background: #0A0A0A !important; border: 1px solid #1E1E1E !important; border-radius: 0 !important; box-shadow: none !important; }
        [data-testid="stTextInput"] > div > div:focus-within { border-color: #FFF !important; }
        [data-testid="stTextInput"] input { background: transparent !important; color: #FFF !important; font-size: 28px !important; letter-spacing: 12px !important; text-align: center !important; caret-color: #FFF !important; border-radius: 0 !important; padding: 16px !important; }
        [data-testid="stTextInput"] input::placeholder { color: #2E2E2E !important; font-size: 20px !important; letter-spacing: 8px !important; }
        [data-testid="stTextInput"] input:focus { box-shadow: none !important; }
        .stButton > button { width: 100% !important; border-radius: 0 !important; font-family: 'Courier New', monospace !important; font-weight: 900 !important; font-size: 11px !important; letter-spacing: 3px !important; text-transform: uppercase !important; padding: 16px 0 !important; line-height: 1 !important; border: none !important; background: #FFF !important; color: #000 !important; transition: opacity 0.15s !important; }
        .stButton > button:hover { opacity: 0.8 !important; background: #FFF !important; }
        .stButton > button:focus { box-shadow: none !important; outline: none !important; }
        .ghost-before + div .stButton > button { background: transparent !important; color: #3A3A3A !important; border: 1px solid #1A1A1A !important; font-size: 10px !important; letter-spacing: 2px !important; }
        .ghost-before + div .stButton > button:hover { border-color: #444 !important; color: #666 !important; opacity: 1 !important; }

        /* ── Responsive / Mobile ── */
        @media (max-width: 768px) {
            .block-container { max-width: 100% !important; padding: 36px 20px 40px !important; }
            [data-testid="stTextInput"] input { font-size: 22px !important; letter-spacing: 8px !important; }
        }
        @media (max-width: 480px) {
            .block-container { padding: 24px 14px 32px !important; }
            [data-testid="stTextInput"] input { font-size: 20px !important; letter-spacing: 6px !important; }
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


def render_otp_verify_page() -> None:
    _css()

    pending_email = st.session_state.get("pending_otp_email", "")

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
            Verify Email
        </div>
        """,
        unsafe_allow_html=True,
    )

    if pending_email:
        st.markdown(
            f"<p style='color:#444;font-size:11px;letter-spacing:1px;text-align:center;"
            f"margin-bottom:36px'>Code sent to "
            f"<span style='color:#888'>{pending_email}</span></p>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<p style='color:#444;font-size:11px;letter-spacing:1px;text-align:center;"
            "margin-bottom:36px'>Enter the 6-digit code from your email.</p>",
            unsafe_allow_html=True,
        )

    msg = st.empty()

    with st.form("otp_verify_form"):
        st.text_input("6-Digit Code", placeholder="000000", max_chars=6, key="otp_code_input")
        _otp_val = st.session_state.get("otp_code_input", "")
        _otp_len = len(_otp_val)
        if _otp_val:
            _dot_color = "#00C96F" if _otp_len == 6 else "#555"
            st.markdown(
                f"<p style='color:{_dot_color};font-size:10px;letter-spacing:3px;"
                f"text-align:center;margin:4px 0'>{_otp_len} / 6</p>",
                unsafe_allow_html=True,
            )
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _submitted = st.form_submit_button("Verify Email", use_container_width=True)

    if _submitted:
        code_val  = st.session_state.get("otp_code_input", "").strip()
        email_val = pending_email or st.session_state.get("signup_email_input", "").strip()

        if not email_val:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Session expired &mdash; please sign up again.</p>",
                unsafe_allow_html=True,
            )
            st.session_state["page"] = "signup"
            st.rerun()
        elif not code_val or not code_val.isdigit() or len(code_val) != 6:
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                "&#9888; Enter the 6-digit numeric code.</p>",
                unsafe_allow_html=True,
            )
        else:
            with st.spinner("Verifying…"):
                remember = st.session_state.get("signin_remember_me", False)
                result = _api.verify_otp(email_val, code_val, remember_me=remember)

            if result["success"]:
                data = result["data"]
                st.session_state.pop("pending_otp_email", None)
                # Auto-login: store tokens + user info returned from verify-otp
                if "access_token" in data:
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
                    msg.markdown(
                        "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        "&#10003; Email verified! Signing you in&hellip;</p>",
                        unsafe_allow_html=True,
                    )
                    st.session_state["page"] = "scan"
                    st.rerun()
                else:
                    msg.markdown(
                        "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        "&#10003; Email verified! You can now sign in.</p>",
                        unsafe_allow_html=True,
                    )
                    st.session_state["page"] = "signin"
                    st.rerun()
            else:
                err = result["error"] or "Verification failed."
                if "expired" in err.lower():
                    msg.markdown(
                        "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        "&#9888; Code expired. Request a new one below.</p>",
                        unsafe_allow_html=True,
                    )
                elif "already verified" in err.lower():
                    msg.markdown(
                        "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        "&#10003; Already verified &mdash; sign in below.</p>",
                        unsafe_allow_html=True,
                    )
                    st.session_state["page"] = "signin"
                    st.rerun()
                else:
                    msg.markdown(
                        f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                        f"&#9888; {err}</p>", unsafe_allow_html=True)

    st.markdown("<div style='margin:32px 0;border-top:1px solid #111'></div>", unsafe_allow_html=True)

    st.markdown(
        "<p style='color:#2A2A2A;font-size:9px;letter-spacing:2px;text-transform:uppercase;"
        "text-align:center;margin:0 0 12px'>Didn't receive a code?</p>",
        unsafe_allow_html=True,
    )
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("Resend Code", use_container_width=True, key="otp_resend_btn"):
        email_val = pending_email or st.session_state.get("signup_email_input", "").strip()
        if not email_val:
            st.session_state["page"] = "signup"
            st.rerun()
        else:
            with st.spinner("Sending…"):
                result = _api.resend_otp(email_val)
            if result["success"]:
                msg.markdown(
                    "<p style='color:#00FF88;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    "&#10003; New code sent! Check your email.</p>",
                    unsafe_allow_html=True,
                )
            else:
                err = result["error"] or "Failed to resend."
                msg.markdown(
                    f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0 0'>"
                    f"&#9888; {err}</p>", unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="ghost-before"></div>', unsafe_allow_html=True)
    if st.button("\u2190 Back to Sign Up", use_container_width=True, key="otp_back_btn"):
        st.session_state["page"] = "signup"
        st.rerun()
 
