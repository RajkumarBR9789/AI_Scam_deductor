"""
ScamShield frontend entry point.

Single-page Streamlit app with manual routing via session state.
Only authenticated pages show a minimal sidebar (History + Sign Out).
"""

import streamlit as st

st.set_page_config(
    page_title="ScamShield",
    page_icon="⚡",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Global CSS: pure black, monospace, kill ALL Streamlit accent / chrome ──
st.markdown(
    """
    <style>
      /* Hide Streamlit chrome */
      #MainMenu, footer, header,
      [data-testid="stHeader"],
      [data-testid="stSidebarNav"],
      [data-testid="stSidebarNavItems"],
      [data-testid="collapsedControl"] { display: none !important; visibility: hidden !important; }

      /* Backgrounds */
      .stApp, section.main, [data-testid="stAppViewContainer"],
      [data-testid="stBottomBlockContainer"] { background: #000 !important; }

      /* Font */
      html, body, *, [class*="css"] {
          font-family: 'Courier New', Courier, monospace !important;
      }

      /* Kill Streamlit's coloured accents (checkboxes, radio, spinner, etc.) */
      [data-testid="stCheckbox"] svg { fill: #FFF !important; }
      [data-testid="stCheckbox"] label span { color: #888 !important; font-size: 11px !important; }
      .stSpinner > div { border-top-color: #FFF !important; }

      /* Selectbox dropdown */
      [data-testid="stSelectbox"] > div > div {
          background: #0A0A0A !important; border: 1px solid #1E1E1E !important;
          border-radius: 0 !important; color: #FFF !important;
      }
      [data-testid="stSelectbox"] svg { fill: #555 !important; }

      /* Toast / alerts */
      [data-testid="stToast"] { background: #111 !important; color: #FFF !important;
          border: 1px solid #222 !important; border-radius: 0 !important; }

      /* Hide "Press Enter to submit form" tooltip */
      small[data-testid="InputInstructions"] { display: none !important; }

      /* ── Responsive / Mobile ── */
      @media (max-width: 768px) {
          .block-container {
              max-width: 100% !important;
              padding-left: 16px !important;
              padding-right: 16px !important;
          }
          section[data-testid="stSidebar"] { width: 260px !important; min-width: 260px !important; }
          .stButton > button, .stFormSubmitButton > button {
              padding: 14px 0 !important;
              font-size: 11px !important;
              min-height: 48px !important;
          }
          [data-testid="stMetric"] { padding: 12px !important; }
          [data-testid="stMetricValue"] { font-size: 22px !important; }
      }
      @media (max-width: 480px) {
          .block-container {
              padding-left: 12px !important;
              padding-right: 12px !important;
          }
          section[data-testid="stSidebar"] { width: 240px !important; min-width: 240px !important; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def _init_session() -> None:
    defaults = {
        "token": None,
        "refresh_token": None,
        "user_email": None,
        "user_name": None,
        "plan_type": "FREE",
        "is_pro": False,
        "session_start": None,
        "last_activity": None,
        "page": "signin",
        "pending_otp_email": None,
    }
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)


def main() -> None:
    _init_session()
    page = st.session_state.get("page", "signin")

    if page == "signup":
        from views.signup import render_signup_page
        render_signup_page()
    elif page == "otp_verify":
        from views.otp_verify import render_otp_verify_page
        render_otp_verify_page()
    elif page == "forgot_password":
        from views.forgot_password import render_forgot_password_page
        render_forgot_password_page()
    elif page == "scan":
        from views.scan import render_scan_page
        render_scan_page()
    elif page == "signout":
        from views.signout import render_signout_page
        render_signout_page()
    elif st.session_state.get("token"):
        from views.scan import render_scan_page
        render_scan_page()
    else:
        from views.signin import render_signin_page
        render_signin_page()


if __name__ == "__main__":
    main()
