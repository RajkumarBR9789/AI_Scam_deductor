"""
Scam Detector — main scan page for ScamShield frontend.
"""

import json
import time

import plotly.graph_objects as go
import streamlit as st

from utils.api_client import APIClient

_api = APIClient()

# ---------------------------------------------------------------------------
# Scan type metadata
# ---------------------------------------------------------------------------

_SCAN_TYPES = {
    "website": {"label": "Website / E-commerce URL", "placeholder": "https://suspicious-ecommerce.com"},
    "job": {"label": "Job Posting / Work-from-home offer", "placeholder": "Paste job description or URL..."},
    "profile": {"label": "Social Media / Dating Profile URL", "placeholder": "https://instagram.com/suspicious_profile"},
    "seller": {"label": "Marketplace Seller / Product Link", "placeholder": "https://olx.in/seller/12345"},
    "email_phone": {"label": "Email Address / Phone Number", "placeholder": "suspicious@gmail.com or +91-9876543210"},
    "upi": {"label": "UPI ID / Payment Request", "placeholder": "scammer@upi or payment link..."},
    "sms": {"label": "SMS / Text Message", "placeholder": "Paste the suspicious SMS text..."},
    "qr_code": {"label": "QR Code URL / Content", "placeholder": "Paste decoded QR content or URL..."},
}

_TYPE_KEYS = list(_SCAN_TYPES.keys())
_TYPE_LABELS = [_SCAN_TYPES[k]["label"] for k in _TYPE_KEYS]


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _css() -> None:
    st.markdown(
        """
        <style>
        .stApp, section.main, [data-testid="stAppViewContainer"],
        [data-testid="stBottomBlockContainer"] { background: #000 !important; }
        [data-testid="stHeader"] { display: none !important; }
        footer { display: none !important; }
        html, body, * { font-family: 'Courier New', Courier, monospace !important; }
        .block-container { max-width: 780px !important; padding: 28px 0 48px !important; margin: 0 auto !important; }

        /* Sidebar */
        section[data-testid="stSidebar"] {
            background: #000 !important;
            border-right: 1px solid #111 !important;
        }
        section[data-testid="stSidebar"] * { font-family: 'Courier New', monospace !important; }
        [data-testid="stSidebarNav"],
        [data-testid="stSidebarNavItems"] { display: none !important; }

        /* Inputs */
        [data-testid="stTextInput"] > div > div,
        [data-testid="stSelectbox"] > div > div {
            background: #0A0A0A !important; border: 1px solid #1E1E1E !important;
            border-radius: 0 !important; box-shadow: none !important;
        }
        [data-testid="stTextInput"] > div > div:focus-within,
        [data-testid="stSelectbox"] > div > div:focus-within { border-color: #FFF !important; }
        [data-testid="stTextInput"] input { background: transparent !important; color: #FFF !important; }
        [data-testid="stTextInput"] label p,
        [data-testid="stSelectbox"] label p {
            color: #555 !important; font-size: 10px !important;
            letter-spacing: 2px !important; text-transform: uppercase !important;
        }

        /* Primary button */
        .stButton > button, .stFormSubmitButton > button {
            width: 100% !important; border-radius: 0 !important;
            font-family: 'Courier New', monospace !important;
            font-weight: 900 !important; font-size: 12px !important;
            letter-spacing: 3px !important; text-transform: uppercase !important;
            padding: 16px 0 !important; border: none !important;
            background: #FFF !important; color: #000 !important;
            transition: opacity 0.15s !important; cursor: pointer !important;
        }
        .stButton > button:hover, .stFormSubmitButton > button:hover { opacity: 0.8 !important; }
        .stButton > button:focus { box-shadow: none !important; outline: none !important; }

        /* Expander */
        [data-testid="stExpander"] {
            border: 1px solid #1E1E1E !important; border-radius: 0 !important;
            background: #0A0A0A !important;
        }
        [data-testid="stExpander"] summary { color: #FFF !important; }
        [data-testid="stExpander"] [data-testid="stMarkdownContainer"] { color: #CCC !important; }

        /* Metric */
        [data-testid="stMetric"] { background: #0A0A0A; padding: 16px; border: 1px solid #1E1E1E; }
        [data-testid="stMetricLabel"] { color: #555 !important; }
        [data-testid="stMetricValue"] { color: #FFF !important; }

        /* Alert overrides */
        [data-testid="stAlert"] {
            background: #0A0A0A !important; border: 1px solid #1E1E1E !important;
            border-radius: 0 !important; color: #CCC !important;
        }

        .risk-badge {
            display: inline-block; padding: 4px 12px; font-size: 11px;
            letter-spacing: 2px; font-weight: 900; text-transform: uppercase;
            margin-top: 4px;
        }
        .risk-safe { background: #34C759; color: #000; }
        .risk-caution { background: #FFD60A; color: #000; }
        .risk-high { background: #FF9F0A; color: #000; }
        .risk-scam { background: #FF453A; color: #FFF; }

        /* Progress bar override */
        [data-testid="stProgress"] > div > div > div {
            background: #FFF !important;
        }

        /* ── Responsive / Mobile ── */
        @media (max-width: 768px) {
            .block-container {
                max-width: 100% !important;
                padding: 16px 16px 40px !important;
            }
            [data-testid="stMetric"] {
                padding: 10px !important;
            }
            [data-testid="stMetricValue"] {
                font-size: 20px !important;
            }
            [data-testid="stMetricLabel"] {
                font-size: 10px !important;
            }
            [data-testid="stExpander"] summary {
                font-size: 13px !important;
            }
        }
        @media (max-width: 480px) {
            .block-container {
                padding: 12px 10px 32px !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_authenticated() -> bool:
    return bool(st.session_state.get("token"))


def _auth_headers() -> dict:
    token = st.session_state.get("token", "")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _risk_color(score: int) -> str:
    if score <= 20:
        return "#34C759"
    if score <= 50:
        return "#FFD60A"
    if score <= 80:
        return "#FF9F0A"
    return "#FF453A"


def _risk_emoji(score: int) -> str:
    if score <= 20:
        return "+"
    if score <= 50:
        return "~"
    return "!"


def _risk_badge_class(label: str) -> str:
    return {
        "SAFE": "risk-safe",
        "CAUTION": "risk-caution",
        "HIGH_RISK": "risk-high",
        "LIKELY_SCAM": "risk-scam",
    }.get(label, "risk-caution")


def _risk_label_display(label: str) -> str:
    return {
        "SAFE": "SAFE",
        "CAUTION": "CAUTION",
        "HIGH_RISK": "HIGH RISK",
        "LIKELY_SCAM": "LIKELY SCAM",
    }.get(label, label)


# ---------------------------------------------------------------------------
# Plotly gauge
# ---------------------------------------------------------------------------

def _render_gauge(score: int) -> None:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 56, "color": "#FFF"}, "suffix": " / 100"},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#555", "dtick": 20,
                         "tickfont": {"color": "#555", "size": 11}},
                "bar": {"color": _risk_color(score), "thickness": 0.75},
                "bgcolor": "#1A1A1A",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 20], "color": "#0f2318"},
                    {"range": [20, 50], "color": "#2a2508"},
                    {"range": [50, 80], "color": "#2a1a08"},
                    {"range": [80, 100], "color": "#2a0e0e"},
                ],
            },
        )
    )
    fig.update_layout(
        paper_bgcolor="#000",
        plot_bgcolor="#000",
        font={"color": "#FFF", "family": "Courier New"},
        height=270,
        margin={"t": 8, "b": 52, "l": 24, "r": 24},
        annotations=[
            dict(x=0.04, y=-0.18, xref="paper", yref="paper",
                 text="SAFE", showarrow=False,
                 font=dict(size=11, color="#34C759", family="Courier New"),
                 xanchor="left"),
            dict(x=0.50, y=-0.18, xref="paper", yref="paper",
                 text="CAUTION", showarrow=False,
                 font=dict(size=11, color="#FFD60A", family="Courier New"),
                 xanchor="center"),
            dict(x=0.96, y=-0.18, xref="paper", yref="paper",
                 text="SCAM", showarrow=False,
                 font=dict(size=11, color="#FF453A", family="Courier New"),
                 xanchor="right"),
        ],
    )
    st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Sidebar — scan history
# ---------------------------------------------------------------------------

def _render_sidebar() -> None:
    with st.sidebar:
        # ── Branding ──
        st.markdown(
            """
            <div style="text-align:center;padding:24px 0 32px">
                <div style="font-size:28px;line-height:1">&#9889;</div>
                <div style="color:#333;font-size:9px;letter-spacing:3px;
                            text-transform:uppercase;margin-top:8px">Scam Shield</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ── History (cached) ──
        st.markdown(
            "<p style='color:#555;font-size:10px;letter-spacing:2px;"
            "text-transform:uppercase;margin-bottom:12px'>History</p>",
            unsafe_allow_html=True,
        )

        # Only fetch history from API when we don't have it cached
        if "history_cache" not in st.session_state:
            result = _api.get(
                "/api/v1/scans/history?limit=10",
                headers=_auth_headers(),
            )
            if result["success"] and result["data"]:
                st.session_state["history_cache"] = result["data"]
            else:
                st.session_state["history_cache"] = []

        history = st.session_state.get("history_cache", [])
        if history:
            for scan in history:
                risk = _risk_emoji(scan["risk_score"])
                short = scan["input_text"][:30]
                if st.sidebar.button(
                    f"[{risk}] {short}",
                    key=f"hist_{scan['scan_id']}",
                    use_container_width=True,
                ):
                    st.session_state["viewing_scan"] = scan["scan_id"]
                    st.session_state.pop("viewing_scan_data", None)
                    st.rerun()
        else:
            st.markdown(
                "<p style='color:#333;font-size:11px'>No scans yet.</p>",
                unsafe_allow_html=True,
            )

        # ── Sign Out ──
        st.markdown(
            "<div style='margin:24px 0;border-top:1px solid #111'></div>",
            unsafe_allow_html=True,
        )
        if st.button("Sign Out", key="sidebar_signout", use_container_width=True):
            refresh = st.session_state.get("refresh_token", "")
            if refresh:
                _api.logout(refresh)
            for key in ("token", "refresh_token", "user_email", "user_name",
                        "plan_type", "is_pro", "session_start", "last_activity",
                        "history_cache", "remaining_cache"):
                st.session_state.pop(key, None)
            st.session_state["page"] = "signin"
            st.rerun()


# ---------------------------------------------------------------------------
# Results rendering
# ---------------------------------------------------------------------------

def _render_results(data: dict) -> None:
    score = data["risk_score"]
    label = data["risk_label"]

    # Risk gauge
    _render_gauge(score)

    badge_cls = _risk_badge_class(label)
    st.markdown(
        f"<div style='text-align:center;margin-bottom:24px'>"
        f"<span class='risk-badge {badge_cls}'>{_risk_label_display(label)}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )

    # Metrics row
    c1, c2, c3 = st.columns(3)
    c1.metric("Scam Risk Score", f"{score}/100")
    c2.metric("Confidence", f"{data['confidence']:.0f}%")
    c3.metric("Type", data["scan_type"].replace("_", " ").title())

    st.markdown(
        "<p style='text-align:center;color:#444;font-size:10px;letter-spacing:1px;margin:6px 0 0'>"
        "0 = Completely Safe &nbsp;·&nbsp; 100 = Confirmed Scam &nbsp;·&nbsp; Higher score = More dangerous</p>",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # Red flags
    red_flags = data.get("red_flags", [])
    with st.expander("Red Flags Found", expanded=True):
        if red_flags:
            for flag in red_flags:
                st.markdown(
                    f"<p style='color:#CCC;font-size:13px;margin:6px 0;padding:8px;"
                    f"border-left:2px solid #555;background:#0A0A0A'>x &nbsp; {flag}</p>",
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                "<p style='color:#888;font-size:13px'>No major red flags detected.</p>",
                unsafe_allow_html=True,
            )

    # AI analysis
    with st.expander("AI Analysis", expanded=True):
        st.markdown(data.get("ai_analysis", ""), unsafe_allow_html=False)
        st.progress(min(data["confidence"] / 100, 1.0))

    # Evidence & citations
    citations = data.get("citations", [])
    with st.expander("Evidence & Sources", expanded=False):
        if citations:
            for cite in citations:
                st.markdown(
                    f"<p style='color:#CCC;font-size:13px;margin:8px 0;padding:8px;"
                    f"border-left:2px solid #333;background:#0A0A0A'>"
                    f"<strong style='color:#FFF'>{cite.get('source', '')}</strong><br>"
                    f"{cite.get('finding', '')}</p>",
                    unsafe_allow_html=True,
                )
                url = cite.get("url", "")
                if url:
                    st.markdown(f"[View Source]({url})")
        else:
            st.markdown(
                "<p style='color:#555'>No external sources found for this scan.</p>",
                unsafe_allow_html=True,
            )

    # Recommendations
    with st.expander("What Should You Do?", expanded=True):
        for rec in data.get("recommendations", []):
            st.markdown(f"- {rec}")

    # Action buttons
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    scan_id = data.get("scan_id", "")

    if _is_authenticated() and scan_id:
        bc1, bc2, bc3 = st.columns(3)
        with bc1:
            if st.button("New Scan", key="back_to_scan", use_container_width=True):
                st.session_state.pop("current_scan_result", None)
                st.session_state.pop("viewing_scan", None)
                st.session_state.pop("viewing_scan_data", None)
                st.rerun()
        with bc2:
            if st.button("Download PDF", key="download_pdf", use_container_width=True):
                import requests as _req
                try:
                    base = _api._base_url
                    resp = _req.get(
                        f"{base}/api/v1/scans/{scan_id}/pdf",
                        headers=_auth_headers(),
                        timeout=15,
                    )
                    if resp.status_code == 200:
                        st.download_button(
                            "Save PDF",
                            data=resp.content,
                            file_name=f"scamshield_{str(scan_id)[:8]}.pdf",
                            mime="application/pdf",
                            key="pdf_download_btn",
                        )
                    else:
                        st.markdown(
                            "<p style='color:#FF3B30;font-size:11px'>PDF generation failed.</p>",
                            unsafe_allow_html=True,
                        )
                except Exception:
                    st.markdown(
                        "<p style='color:#FF3B30;font-size:11px'>Could not generate PDF.</p>",
                        unsafe_allow_html=True,
                    )
        with bc3:
            if st.button("Copy Report", key="copy_report_btn", use_container_width=True):
                report_text = (
                    f"ScamShield Report\n"
                    f"Risk: {data.get('risk_score', 0)}/100 ({data.get('risk_label', '')})\n"
                    f"Input: {data.get('input_text', '')[:80]}\n"
                    f"Scan ID: {scan_id}"
                )
                st.code(report_text, language=None)
    else:
        # Guest: show new scan button + sign-in prompt
        if st.button("New Scan", key="back_to_scan_guest", use_container_width=True):
            st.session_state.pop("current_scan_result", None)
            st.session_state.pop("viewing_scan", None)
            st.session_state.pop("viewing_scan_data", None)
            st.rerun()
        st.markdown(
            "<p style='color:#555;font-size:11px;letter-spacing:1px;margin:12px 0 8px'>"
            "Sign in to save history & download PDF.</p>",
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Sign In", key="guest_signin_btn", use_container_width=True):
                st.session_state["page"] = "signin"
                st.rerun()
        with c2:
            if st.button("Create Account", key="guest_signup_btn", use_container_width=True):
                st.session_state["page"] = "signup"
                st.rerun()


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

def render_scan_page() -> None:
    _css()
    is_auth = _is_authenticated()

    # Sidebar (history + sign-out) only for authenticated users
    if is_auth:
        _render_sidebar()

    # -- Header --
    email = st.session_state.get("user_email", "")

    # Remaining scans counter (only relevant for authenticated users)
    remaining_txt = ""
    if is_auth:
        if "remaining_cache" not in st.session_state:
            remaining_result = _api.get("/api/v1/scans/remaining", headers=_auth_headers())
            if remaining_result["success"]:
                st.session_state["remaining_cache"] = remaining_result["data"]
        r = st.session_state.get("remaining_cache")
        if r:
            if r["plan"] == "free":
                remaining_txt = f"{r['remaining']}/{r['limit']} scans left today"
            else:
                remaining_txt = "Unlimited scans"

    st.markdown(
        f"""
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div>
                <div style="color:#333;font-size:10px;letter-spacing:4px;text-transform:uppercase">Scam Shield</div>
            </div>
            <div style="color:#333;font-size:11px;letter-spacing:1px">{email}</div>
        </div>
        <div style="text-align:center;padding:0 0 8px">
            <div style="font-size:42px;line-height:1">&#9889;</div>
            <div style="color:#FFF;font-size:22px;font-weight:900;letter-spacing:5px;
                        text-transform:uppercase;margin:12px 0 4px">AI Scam Detector</div>
            <div style="color:#444;font-size:12px;letter-spacing:2px">
                Verify before you trust.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not is_auth:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Sign In", key="hdr_signin", use_container_width=True):
                st.session_state["page"] = "signin"
                st.rerun()
        with c2:
            if st.button("Create Account", key="hdr_signup", use_container_width=True):
                st.session_state["page"] = "signup"
                st.rerun()
        st.markdown(
            "<p style='text-align:center;color:#333;font-size:11px;letter-spacing:1px;margin:8px 0 16px'>"
            "Guest mode — results are not saved.</p>",
            unsafe_allow_html=True,
        )

    if remaining_txt:
        st.markdown(
            f"<p style='text-align:center;color:#444;font-size:11px;letter-spacing:1px;"
            f"margin-bottom:24px'>{remaining_txt}</p>",
            unsafe_allow_html=True,
        )

    # -- If we already have a result in session state, show it (no form below) --
    if "current_scan_result" in st.session_state:
        _render_results(st.session_state["current_scan_result"])
        return

    # -- Load scan from history if requested --
    viewing_id = st.session_state.get("viewing_scan")
    if viewing_id:
        cached = st.session_state.get("viewing_scan_data")
        if cached and cached.get("scan_id") == viewing_id:
            _render_results(cached)
            return
        with st.spinner("Loading scan…"):
            res = _api.get(f"/api/v1/scans/{viewing_id}", headers=_auth_headers())
        if res["success"]:
            st.session_state["viewing_scan_data"] = res["data"]
            _render_results(res["data"])
            return
        else:
            st.session_state.pop("viewing_scan", None)
            st.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0'>"
                "Failed to load scan. Showing scan form.</p>",
                unsafe_allow_html=True,
            )

    # -- Scan input form --
    with st.form("scan_form"):
        type_idx = st.selectbox(
            "What do you want to check?",
            options=range(len(_TYPE_KEYS)),
            format_func=lambda i: _TYPE_LABELS[i],
            key="scan_type_select",
        )
        selected_key = _TYPE_KEYS[type_idx]
        placeholder = _SCAN_TYPES[selected_key]["placeholder"]

        input_text = st.text_input(
            "Enter URL, email, phone, or description",
            placeholder=placeholder,
            key="scan_input_text",
        )

        submitted = st.form_submit_button("Analyze Now", use_container_width=True)

    msg = st.empty()

    if submitted:
        if not input_text or not input_text.strip():
            msg.markdown(
                "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0'>"
                "&#9888; Please enter something to analyze.</p>",
                unsafe_allow_html=True,
            )
            return

        with st.spinner("Analyzing…"):
            status_area = st.empty()
            steps = [
                "Searching fraud reports and scam databases…",
                "Analyzing patterns with AI…",
                "Calculating risk score…",
            ]
            for step in steps:
                status_area.info(step)
                time.sleep(0.5)

            result = _api.post(
                "/api/v1/scans/analyze",
                json={"input_text": input_text.strip(), "scan_type": selected_key},
                headers=_auth_headers(),
                timeout=90,
            )
            status_area.empty()

        if result["success"]:
            # Store result in session state, then rerun to show results only (no form)
            st.session_state["current_scan_result"] = result["data"]
            st.session_state.pop("history_cache", None)
            st.session_state.pop("remaining_cache", None)
            st.rerun()
        else:
            err = result.get("error", "")
            if "429" in str(err) or "limit" in str(err).lower():
                msg.markdown(
                    "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0'>"
                    "Daily scan limit reached. Upgrade to Pro for unlimited scans.</p>",
                    unsafe_allow_html=True,
                )
            elif "401" in str(err) or "expired" in str(err).lower() or "revoked" in str(err).lower():
                msg.markdown(
                    "<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0'>"
                    "Session expired. Please sign in again.</p>",
                    unsafe_allow_html=True,
                )
                st.session_state["page"] = "signin"
                st.rerun()
            else:
                msg.markdown(
                    f"<p style='color:#FF3B30;font-size:12px;letter-spacing:1px;margin:12px 0'>"
                    f"Analysis failed: {err}</p>",
                    unsafe_allow_html=True,
                )
