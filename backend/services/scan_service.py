"""
Business-logic helpers for scam-detection scans.

Provides:
- domain_analysis
- search_fraud_reports (SerpAPI)
- check_phishing_databases
- compile_red_flags / score
- generate_ai_analysis (Groq LLM)
"""

import json
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from config import settings

# ---------------------------------------------------------------------------
# URL shortener domains used for detection
# ---------------------------------------------------------------------------
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "qr.io", "tiny.cc", "shorturl.at", "clck.ru",
}

# Suspicious TLDs frequently used in scam sites
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".win", ".loan", ".gq", ".ml",
    ".cf", ".tk", ".work", ".online", ".site", ".info",
    ".buzz", ".club", ".live", ".shop", ".store", ".fun",
    ".racing", ".trade", ".download", ".review", ".science",
    ".accountant", ".faith", ".date", ".stream",
}

# Well-known brands commonly impersonated in phishing
_KNOWN_BRANDS = {
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "twitter", "whatsapp", "youtube",
    "bank", "hdfc", "sbi", "icici", "axis", "kotak", "pnb", "rbi",
    "paytm", "phonepe", "gpay", "flipkart", "myntra",
    "naukri", "indeed", "linkedin", "swiggy", "zomato",
    "ola", "uber", "irdai", "sebi", "income-tax",
}

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Keywords in domain name that indicate phishing/fake sites
_PHISHING_DOMAIN_KEYWORDS = {
    "login", "secure", "verify", "update", "confirm", "account",
    "webscr", "signin", "banking", "support", "helpdesk",
    "password", "reset", "validation", "alert", "notification",
    "service", "checkout", "payment", "invoice", "billing",
}

# Suspicious keywords in URL path indicating phishing flows
_PHISHING_PATH_KEYWORDS = {
    "/login", "/signin", "/verify", "/secure", "/update",
    "/confirm", "/account", "/password", "/reset", "/validation",
    "/webscr", "/checkout", "/payment", "/invoice",
}

# Text-based scam signal patterns per scan type
_TEXT_PATTERNS: dict[str, list[str]] = {
    "sms": [
        r"\b(won|winner|winning)\b",
        r"\blottery\b",
        r"\bcongratulation",
        r"\bclaim\s+(your\s+)?(prize|reward|cash)",
        r"\b(verify|update|confirm)\s+(your\s+)?account",
        r"\bsuspend(ed|ing)?\b",
        r"\botp\b.{0,30}\bshare\b",
        r"\bshare\s+(the\s+)?otp\b",
        r"\bkbc\b",
        r"\bfree\s+(gift|iphone|samsung|laptop)",
        r"\brefund\b.{0,40}\bclick\b",
        r"\bcustomer\s+care\b.{0,30}\b\d{7,}\b",
        r"\bdebit\s+card\b.{0,30}\b(expire|block|suspend)",
        r"\bclick\s+(here|below)\b.{0,50}https?://",
        r"\b(rs|inr)\.?\s*\d{4,}\b.{0,30}\b(credit|transfer|send)\b",
    ],
    "email_phone": [
        r"\b(won|winner|winning)\b",
        r"\blottery\b",
        r"\blucky\s+draw\b",
        r"\bprize\s+(money|amount|fund)",
        r"\bsend\s+(money|rs\.?|inr|amount|cash)",
        r"\btransfer\s+\d",
        r"\badvance\s+(fee|charge|payment)",
        r"\binheritance\b",
        r"\bwork\s+from\s+home\b.{0,30}\bper\s+day\b",
        r"\b\d{4,}\s*(rs|rupees|inr)\s*per\s*(day|week|hour)",
        r"\bgift\s+card\b",
        r"\bitunes\b.{0,20}\bcard\b",
        r"\bunclaimed\b.{0,30}\b(fund|benefit|prize)",
    ],
    "job": [
        r"\bwork\s+from\s+home\b",
        r"\bdata\s+(entry|typing)\b.{0,30}\bearning\b",
        r"\bno\s+experience\b.{0,30}\bearning\b",
        r"\b\d{4,}\s*(rs|rupees|inr)\s*per\s*(day|hour|week)\b",
        r"\bregistration\s+fee\b",
        r"\bdeposit\b.{0,30}\bjoin\b",
        r"\bguaranteed\s+(income|earning|salary)\b",
        r"\bpart.?time\b.{0,40}\b\d{3,}\s*(rs|rupees|inr)\b",
        r"\blike\s+(video|photos)\b.{0,30}\b(earn|paid|money)\b",
        r"\bno\s+investment\b.{0,30}\bearn\b",
    ],
    "upi": [
        r"\bpay\b.{0,30}\bget\s+(double|2x|\d+x)\b",
        r"\bkbc\b",
        r"\blottery\b",
        r"\bprize\b",
        r"\bcustomer\s+care\b",
        r"\bcashback\b.{0,30}\bsend\b",
        r"\bverify\s+(upi|account|payment)\b",
        r"\bqr\s+code\b.{0,30}\b(scan|pay)\b.{0,30}\b(get|earn|receive)\b",
    ],
    "profile": [
        r"\bsend\s*(me\s*)?(money|gift|card)\b",
        r"\bstranded\b",
        r"\bemergency\b.{0,50}\bmoney\b",
        r"\bitunes\b",
        r"\bgift\s+card\b",
        r"\bmilitary\b.{0,60}\b(money|help|fund)\b",
        r"\binheritance\b",
        r"\ball\s+my\s+(money|fund)\b",
        r"\bonline\s+(love|romance|partner)\b",
    ],
    "qr_code": [
        r"\bscan\b.{0,30}\b(win|earn|get\s+\d)\b",
        r"\bverify\b.{0,30}\bscan\b",
        r"\bpay\b.{0,30}\bscan\b.{0,30}\bget\b",
    ],
    "seller": [
        r"\b(advance|upfront)\s+(payment|deposit|charge)\b",
        r"\bpay\s+first\b.{0,30}\b(ship|deliver|send)\b",
        r"\bno\s+return\b",
        r"\btoo\s+good\s+to\s+be\s+true\b",
        r"\b\d{2,}%\s*off\b.{0,30}\b(original|mrp|retail)\b",
        r"\bwhatsapp\s+(only|me|number)\b",
        r"\bdo\s+not\s+(use\s+)?upi\b",
        r"\boutside\s+(platform|app|site)\b",
        r"\bcash\s+on\s+delivery\s+not\s+available\b",
    ],
}


# ---------------------------------------------------------------------------
# STEP 1 — Domain analysis (WHOIS + SSL)
# ---------------------------------------------------------------------------

async def domain_analysis(input_text: str) -> dict[str, Any]:
    """Analyse domain age, SSL validity, shortener usage, and structural signals for a URL."""
    try:
        parsed = urlparse(input_text)
        domain = parsed.hostname
        if not domain:
            return {}

        result: dict[str, Any] = {"domain": domain}
        domain_lower = domain.lower()

        # URL shortener?
        result["is_url_shortener"] = domain_lower in _SHORTENER_DOMAINS

        # Raw IP address instead of domain name?
        result["is_ip_hostname"] = bool(_IP_PATTERN.match(domain_lower))

        # Suspicious TLD?
        result["suspicious_tld"] = any(domain_lower.endswith(tld) for tld in _SUSPICIOUS_TLDS)

        # Brand name in subdomain but not root (e.g. paypal.evil.com)
        parts = domain_lower.split(".")
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            root_domain = ".".join(parts[-2:])
            result["brand_in_subdomain"] = any(
                brand in subdomain and brand not in root_domain
                for brand in _KNOWN_BRANDS
            )
        else:
            result["brand_in_subdomain"] = False

        # Non-standard port in URL?
        result["has_port"] = bool(parsed.port and parsed.port not in (80, 443))

        # Excessive subdomain depth (e.g. a.b.c.d.evil.com)
        result["excessive_subdomains"] = len(parts) > 5

        # Suspicious keywords in domain name (e.g. secure-paypal.com, login-hdfc.net)
        domain_nodots = domain_lower.replace("-", "").replace(".", "")
        result["phishing_keyword_in_domain"] = any(
            kw in domain_nodots for kw in _PHISHING_DOMAIN_KEYWORDS
        )

        # Excessive hyphens (e.g. pay-pal-secure-login.com)
        result["many_hyphens"] = domain_lower.count("-") >= 3

        # Very long domain name (legit sites rarely exceed 30 chars)
        result["long_domain"] = len(domain_lower) > 30

        # Suspicious path keywords (e.g. example.com/login/verify)
        url_path = (parsed.path or "").lower()
        result["suspicious_path"] = any(kw in url_path for kw in _PHISHING_PATH_KEYWORDS)

        # Domain age via python-whois (network I/O — run in thread)
        try:
            import whois  # type: ignore[import-untyped]

            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.now(timezone.utc) - creation_date.replace(
                    tzinfo=creation_date.tzinfo or timezone.utc
                )).days
                result["domain_age_days"] = max(age_days, 0)
        except Exception:
            pass

        # SSL validity
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    result["ssl_valid"] = True
        except Exception:
            result["ssl_valid"] = False

        return result
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# STEP 2 — SerpAPI fraud-report search
# ---------------------------------------------------------------------------

def _build_queries(input_text: str, scan_type: str) -> list[str]:
    """Return up to three search queries tailored to the scan type."""
    short = input_text[:80]
    parsed_domain = ""
    try:
        parsed_domain = urlparse(input_text).hostname or ""
    except Exception:
        pass

    lookup = {
        "website": [
            f'"{parsed_domain}" scam OR fraud',
            f'"{parsed_domain}" fake OR phishing OR scam report',
            f'"{parsed_domain}" reviews complaints',
        ],
        "seller": [
            f'"{parsed_domain or short}" scam seller OR fake',
            f'"{short}" fraud report OR complaints',
            f'"{short}" cheated OR victim',
        ],
        "job": [
            f'"{short}" scam job OR fake job',
            f'"{short}" work from home fraud',
            f'"{short}" fake recruiter OR job scam India',
        ],
        "profile": [
            f'"{short}" scammer OR fake profile',
            f'"{short}" catfish OR romance scam',
            f'"{short}" reported fraud OR impersonation',
        ],
        "email_phone": [
            f'"{short}" scam OR fraud',
            f'"{short}" spam reported OR complaints',
            f'"{short}" phishing OR smishing',
        ],
        "upi": [
            f'"{short}" UPI scam OR fraud',
            f'"{short}" UPI fraud payment India',
            f'"{short}" fake payment request',
        ],
        "sms": [
            f'"{short}" SMS scam OR phishing',
            f'"{short}" smishing OR fake text message',
            f'"{short}" reported fraud SMS',
        ],
        "qr_code": [
            f'"{short}" QR code scam',
            f'"{short}" fraudulent QR payment',
        ],
    }
    return lookup.get(scan_type, [f'"{short}" scam OR fraud'])


async def search_fraud_reports(
    input_text: str, scan_type: str
) -> list[dict[str, str]]:
    """Query SerpAPI for fraud reports. Returns up to 10 citations."""
    if not settings.SERPAPI_KEY:
        return []

    queries = _build_queries(input_text, scan_type)
    citations: list[dict[str, str]] = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        for query in queries:
            if len(citations) >= 10:
                break
            try:
                resp = await client.get(
                    "https://serpapi.com/search",
                    params={
                        "q": query,
                        "api_key": settings.SERPAPI_KEY,
                        "num": 5,
                        "engine": "google",
                    },
                )
                resp.raise_for_status()
                for item in resp.json().get("organic_results", []):
                    if len(citations) >= 10:
                        break
                    citations.append({
                        "source": item.get("title", ""),
                        "finding": item.get("snippet", ""),
                        "url": item.get("link", ""),
                    })
            except Exception:
                continue

    return citations


# ---------------------------------------------------------------------------
# STEP 3 — Phishing database checks
# ---------------------------------------------------------------------------

async def check_phishing_databases(input_text: str) -> dict[str, bool]:
    """Check PhishTank + Google Safe Browsing for the given URL."""
    result = {"phishtank_flagged": False, "google_safe_browsing_flagged": False}

    async with httpx.AsyncClient(timeout=10.0) as client:
        # PhishTank
        try:
            resp = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": input_text, "format": "json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                result["phishtank_flagged"] = bool(
                    data.get("results", {}).get("in_database")
                )
        except Exception:
            pass

        # Google Safe Browsing
        gsb_key = settings.GOOGLE_SAFE_BROWSING_KEY
        if gsb_key:
            try:
                resp = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
                    json={
                        "client": {"clientId": "scamshield", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": input_text}],
                        },
                    },
                )
                if resp.status_code == 200 and resp.json().get("matches"):
                    result["google_safe_browsing_flagged"] = True
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------------
# STEP 4 — Compile red flags & score
# ---------------------------------------------------------------------------

_FRAUD_KEYWORDS = {
    "scam", "fraud", "fake", "cheat", "phishing",
    "suspicious", "warning", "avoid", "beware",
    "complaint", "reported", "blacklist", "alert",
    "cheated", "duped", "victim", "smishing", "vishing",
    "impersonat", "stolen", "unauthorized", "deceptive",
}


def compile_red_flags(
    domain_info: dict[str, Any],
    search_results: list[dict[str, str]],
    phishing_info: dict[str, bool],
    input_text: str = "",
    scan_type: str = "",
) -> tuple[list[str], int, str]:
    """Return (red_flags, risk_score 0-100, risk_label)."""
    red_flags: list[str] = []
    score = 0

    # Domain age
    age = domain_info.get("domain_age_days", 999)
    if age < 30:
        red_flags.append(f"Domain only {age} days old (very new)")
        score += 30
    elif age < 180:
        red_flags.append("Domain less than 6 months old")
        score += 15

    # SSL
    if domain_info.get("ssl_valid") is False:
        red_flags.append("No valid SSL certificate (connection not encrypted)")
        score += 25

    # URL shortener
    if domain_info.get("is_url_shortener"):
        red_flags.append("Uses URL shortener to hide real destination")
        score += 20

    # IP-based hostname
    if domain_info.get("is_ip_hostname"):
        red_flags.append("URL uses a raw IP address instead of a domain name")
        score += 25

    # Suspicious TLD
    if domain_info.get("suspicious_tld"):
        red_flags.append("Domain uses a suspicious top-level domain (.xyz, .top, .click, etc.)")
        score += 15

    # Brand spoofing in subdomain
    if domain_info.get("brand_in_subdomain"):
        red_flags.append("Domain appears to impersonate a known brand (brand name in subdomain)")
        score += 35

    # Non-standard port
    if domain_info.get("has_port"):
        red_flags.append("URL uses a non-standard port number (uncommon for legitimate sites)")
        score += 10

    # Excessive sub-domains
    if domain_info.get("excessive_subdomains"):
        red_flags.append("Unusually deep subdomain structure (common in phishing URLs)")
        score += 10

    # Phishing-related keyword embedded in domain name
    if domain_info.get("phishing_keyword_in_domain"):
        red_flags.append(
            "Domain name contains a phishing-related keyword (login/verify/secure/payment/etc.)"
        )
        score += 20

    # Too many hyphens in domain (e.g. paypal-secure-login-verify.tk)
    if domain_info.get("many_hyphens"):
        red_flags.append(
            "Domain contains excessive hyphens - a common pattern in scam/phishing domains"
        )
        score += 15

    # Abnormally long domain name
    if domain_info.get("long_domain"):
        red_flags.append(
            "Unusually long domain name (frequently used to disguise phishing URLs)"
        )
        score += 10

    # Suspicious keywords in URL path (/login, /verify, /checkout, etc.)
    if domain_info.get("suspicious_path"):
        red_flags.append(
            "URL path contains authentication or payment keywords - typical of phishing flows"
        )
        score += 15

    # Phishing databases
    if phishing_info.get("phishtank_flagged"):
        red_flags.append("⚠️ Listed in PhishTank phishing database")
        score += 40
    if phishing_info.get("google_safe_browsing_flagged"):
        red_flags.append("⚠️ Flagged by Google Safe Browsing")
        score += 40

    # Fraud mentions in search results
    fraud_mentions = 0
    for item in search_results:
        text = (item.get("finding", "") + " " + item.get("source", "")).lower()
        if any(kw in text for kw in _FRAUD_KEYWORDS):
            fraud_mentions += 1
    if fraud_mentions >= 5:
        red_flags.append(f"Found {fraud_mentions} fraud reports/warnings online")
        score += 30
    elif fraud_mentions >= 2:
        red_flags.append(f"Found {fraud_mentions} suspicious mentions online")
        score += 15
    elif fraud_mentions == 1:
        red_flags.append("Found 1 potential fraud mention online")
        score += 8

    # Text-pattern analysis for non-URL scan types
    if input_text and scan_type in _TEXT_PATTERNS:
        text_lower = input_text.lower()
        matched_patterns: list[str] = []
        for pattern in _TEXT_PATTERNS[scan_type]:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matched_patterns.append(pattern)
        if len(matched_patterns) >= 3:
            red_flags.append(f"Text contains {len(matched_patterns)} known scam language patterns")
            score += 35
        elif len(matched_patterns) == 2:
            red_flags.append("Text contains multiple scam language indicators")
            score += 20
        elif len(matched_patterns) == 1:
            red_flags.append("Text contains a known scam language pattern")
            score += 10

    final_score = min(score, 100)

    if final_score <= 20:
        risk_label = "SAFE"
    elif final_score <= 50:
        risk_label = "CAUTION"
    elif final_score <= 80:
        risk_label = "HIGH_RISK"
    else:
        risk_label = "LIKELY_SCAM"

    return red_flags, final_score, risk_label


# ---------------------------------------------------------------------------
# STEP 5 — LLM analysis via Groq
# ---------------------------------------------------------------------------

def _build_recommendations(risk_label: str, scan_type: str = "") -> list[str]:
    """Generate action-item recommendations based on risk label and scan type."""

    # Type-specific tips to append at the end
    _type_tips: dict[str, list[str]] = {
        "upi": [
            "Never scan a QR code to receive money - receiving money never requires scanning.",
            "Verify the payee name shown before confirming any UPI transaction.",
            "Report UPI fraud to your bank's helpline and NPCI helpline 1800-120-1740.",
        ],
        "job": [
            "Legitimate employers never ask for a registration/training/security deposit fee.",
            "Verify company registration on the MCA21 portal (mcav3.mca.gov.in).",
            "Cross-check the job posting on the company's official website.",
        ],
        "sms": [
            "Block this number immediately using your phone's dialler app.",
            "Report spam SMS to TRAI via 1909 or the SANCHAR SAATHI portal.",
            "Never click links in unsolicited SMS messages.",
        ],
        "seller": [
            "Pay only through the platform's official payment gateway - never directly.",
            "Avoid sellers who insist on advance payment or UPI outside the platform.",
            "Check seller ratings, reviews, and account age before buying.",
        ],
        "profile": [
            "Reverse-image-search profile photos to check for stolen images.",
            "Never send money to someone you have not met in person.",
            "Report the profile to the platform and to cybercrime.gov.in.",
        ],
        "qr_code": [
            "Use 'Scan & Pay' in your UPI app - do NOT use 'Scan to Receive'.",
            "Inspect the physical QR code sticker for tampering.",
            "Confirm the merchant name displayed after scanning before paying.",
        ],
        "email_phone": [
            "Do not call back unknown numbers - use Truecaller to verify first.",
            "Legitimate banks/UIDAI never ask for OTP or CVV over phone or email.",
            "Report phishing emails to report@phishing.gov.in.",
        ],
        "website": [
            "Check the padlock/HTTPS and ensure the domain spelling is correct.",
            "Look up the site on Whois to verify domain age and ownership.",
        ],
    }

    if risk_label == "LIKELY_SCAM":
        base = [
            "Do NOT share any personal or financial information.",
            "Do NOT make any payments or transfers.",
            "Report immediately at cybercrime.gov.in or call 1930.",
            "Block and report on the originating platform.",
            "Warn friends and family about this scam.",
        ]
    elif risk_label == "HIGH_RISK":
        base = [
            "Exercise extreme caution before interacting further.",
            "Verify through official channels independently before proceeding.",
            "Do not share sensitive or financial information.",
            "Search online for additional reviews and fraud reports.",
            "Consider reporting to cybercrime.gov.in.",
        ]
    elif risk_label == "CAUTION":
        base = [
            "Proceed with caution and verify thoroughly before acting.",
            "Confirm through official channels before sharing any data.",
            "Use a virtual card if a payment is necessary.",
        ]
    else:
        base = [
            "Appears legitimate, but always stay vigilant.",
            "Never share OTPs or passwords regardless of the requester.",
        ]

    for tip in _type_tips.get(scan_type, []):
        if tip not in base:
            base.append(tip)
    return base


async def generate_ai_analysis(
    scan_type: str,
    input_text: str,
    domain_info: dict[str, Any],
    risk_score: int,
    red_flags: list[str],
    fraud_mentions: int,
    search_results: list[dict[str, str]],
) -> tuple[str, float]:
    """
    Call Groq LLM for a detailed markdown analysis.

    Returns (analysis_markdown, confidence_percent).
    """
    if not settings.GROQ_API_KEY:
        return _fallback_analysis(risk_score, red_flags), 50.0

    prompt = f"""You are an expert cybersecurity analyst specialising in online fraud detection for India.

Analyse the following input and determine if it is a scam or fraud.

=== INPUT DETAILS ===
Scan Type  : {scan_type}
Input      : {input_text}
Domain Age : {domain_info.get('domain_age_days', 'N/A')} days
SSL Valid  : {domain_info.get('ssl_valid', 'N/A')}
IP Hostname: {domain_info.get('is_ip_hostname', False)}
Brand Spoofing: {domain_info.get('brand_in_subdomain', False)}
Suspicious TLD: {domain_info.get('suspicious_tld', False)}
Risk Score : {risk_score}/100
Red Flags  : {json.dumps(red_flags)}
Online Fraud Mentions: {fraud_mentions}
Top Search Findings:
{json.dumps([r['finding'] for r in search_results[:5]], indent=2)}

=== SCAN TYPE CONTEXT ===
""" + {
        "website":     "Analyse the URL for phishing, fake e-commerce, and brand impersonation.",
        "job":         "Analyse for fake job offers, advance-fee fraud, and work-from-home scams common in India.",
        "profile":     "Analyse for romance scams, catfishing, and social engineering via fake social profiles.",
        "seller":      "Analyse for fake marketplace sellers, counterfeit goods, and payment fraud.",
        "email_phone": "Analyse for phishing emails, smishing (SMS phishing), vishing (voice phishing), and spam.",
        "upi":         "Analyse for fake UPI payment requests, QR-code payment fraud, and UPI ID impersonation.",
        "sms":         "Analyse for smishing (SMS phishing), prize/lottery scams, and OTP theft attempts.",
        "qr_code":     "Analyse for malicious QR codes used in payment fraud or redirection to phishing sites.",
    }.get(scan_type, "Analyse for all common scam patterns.") + f"""

Provide your analysis using EXACTLY these markdown sections:

## 🔍 Summary
(2–3 sentence verdict. State clearly if this appears to be a scam, suspicious, or safe.)

## 📋 Detailed Findings
(Bullet points of specific evidence. Cite each red flag with an explanation.)

## ⚠️ Warning Signs
(Plain-language explanation of each red flag found. Say why each is suspicious.)

## ✅ Recommendations
(Numbered list of 4–6 specific actionable steps the user should take.)

## 📊 Confidence Assessment
(State your confidence level and why. Mention any limitations or missing data.)

IMPORTANT:
- Be factual. Phrase conclusions as "appears to be" or "shows signs of".
- If the input seems legitimate, say so clearly — do not force a negative verdict.
- Always end with: *Disclaimer: This is an automated analysis for informational purposes only.*
"""

    try:
        from groq import Groq

        client = Groq(api_key=settings.GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior cybersecurity analyst specialising in online scam "
                        "and fraud detection for India. You evaluate digital inputs such as "
                        "URLs, phone numbers, SMS messages, UPI IDs, job postings, and social "
                        "media profiles. Always cite specific evidence. Never fabricate "
                        "findings. When evidence is insufficient, state that clearly."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=2048,
        )
        analysis = response.choices[0].message.content or ""
        confidence = _estimate_confidence(risk_score, red_flags, search_results)
        return analysis, confidence
    except Exception:
        return _fallback_analysis(risk_score, red_flags), 40.0


def _estimate_confidence(
    risk_score: int,
    red_flags: list[str],
    search_results: list[dict[str, str]],
) -> float:
    """Heuristic confidence based on how much evidence was gathered."""
    base = 45.0
    if red_flags:
        base += min(len(red_flags) * 7, 25)
    if search_results:
        base += min(len(search_results) * 4, 20)
    if risk_score > 70:
        base += 10
    elif risk_score > 40:
        base += 5
    # Phishing DB hit = near-certainty
    if any("PhishTank" in f or "Safe Browsing" in f for f in red_flags):
        base += 15
    # Domain age data present = more concrete evidence
    if any("days old" in f for f in red_flags):
        base += 5
    return min(base, 95.0)


def _fallback_analysis(risk_score: int, red_flags: list[str]) -> str:
    """Produce a basic analysis when the LLM is unavailable."""
    flags_md = "\n".join(f"- {f}" for f in red_flags) if red_flags else "- None detected"
    return (
        f"## 🔍 Summary\n"
        f"Risk score is **{risk_score}/100**.  "
        f"{'Use extreme caution.' if risk_score > 50 else 'Low to moderate risk detected.'}\n\n"
        f"## ⚠️ Warning Signs\n{flags_md}\n\n"
        "## 📊 Confidence Assessment\n"
        "This is a rule-based analysis because LLM analysis was unavailable. "
        "Confidence is lower than normal.\n\n"
        "---\n*Disclaimer: This is informational analysis only.*"
    )
