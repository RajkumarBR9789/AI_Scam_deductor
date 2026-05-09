"""
PDF report generator for ScamShield scan results.

Uses fpdf2 to produce a clean single-page PDF with:
- Header with branding
- Risk score summary
- Red flags
- AI analysis (truncated to fit)
- Recommendations
- Footer with disclaimer
"""

import io
import textwrap
from datetime import datetime, timezone

from fpdf import FPDF


class _ScamShieldPDF(FPDF):
    """Custom PDF with ScamShield header/footer."""

    def header(self):
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 12, "ScamShield Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, "Detect. Protect. Trust.", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(6)

    def footer(self):
        self.set_y(-20)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(140, 140, 140)
        self.cell(
            0, 8,
            "Disclaimer: This report is for informational purposes only and does not constitute legal advice.",
            align="C",
        )


def generate_pdf_report(scan_data: dict) -> bytes:
    """Generate a PDF report from a scan result dict. Returns PDF bytes."""
    pdf = _ScamShieldPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=25)

    # -- Scan metadata --
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Scan Details", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)

    scan_type_display = scan_data.get("scan_type", "").replace("_", " ").title()
    input_text = scan_data.get("input_text", "")
    if len(input_text) > 120:
        input_text = input_text[:117] + "..."
    created = scan_data.get("created_at", "")
    if isinstance(created, datetime):
        created = created.strftime("%Y-%m-%d %H:%M UTC")
    elif isinstance(created, str) and len(created) > 19:
        created = created[:19].replace("T", " ") + " UTC"

    for label, value in [
        ("Type", scan_type_display),
        ("Input", input_text),
        ("Date", created),
        ("Scan ID", str(scan_data.get("scan_id", ""))),
    ]:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(25, 6, f"{label}:")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)

    # -- Risk score box --
    risk_score = scan_data.get("risk_score", 0)
    risk_label = scan_data.get("risk_label", "UNKNOWN")
    confidence = scan_data.get("confidence", 0)

    pdf.set_font("Helvetica", "B", 12)
    label_display = risk_label.replace("_", " ")
    pdf.cell(0, 10, f"Risk Score: {risk_score}/100  |  {label_display}  |  Confidence: {confidence:.0f}%",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # -- Red flags --
    red_flags = scan_data.get("red_flags", [])
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Warning Signs", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    if red_flags:
        for flag in red_flags:
            clean = flag.encode("ascii", "replace").decode()
            pdf.cell(6, 5, "-")
            pdf.multi_cell(0, 5, f" {clean}", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 5, "No major red flags detected.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # -- AI analysis (truncated) --
    ai_analysis = scan_data.get("ai_analysis", "")
    if ai_analysis:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "AI Analysis", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        # Strip markdown headers for PDF
        lines = ai_analysis.replace("##", "").replace("**", "").split("\n")
        for line in lines[:40]:
            clean = line.strip().encode("ascii", "replace").decode()
            if clean:
                pdf.multi_cell(0, 5, clean, new_x="LMARGIN", new_y="NEXT")
        if len(lines) > 40:
            pdf.set_font("Helvetica", "I", 8)
            pdf.cell(0, 5, "[Analysis truncated — see full report online]", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # -- Recommendations --
    recs = scan_data.get("recommendations", [])
    if recs:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Recommendations", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for i, rec in enumerate(recs, 1):
            clean = rec.encode("ascii", "replace").decode()
            pdf.multi_cell(0, 5, f"{i}. {clean}", new_x="LMARGIN", new_y="NEXT")

    # -- Citations --
    citations = scan_data.get("citations", [])
    if citations:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Sources", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for cite in citations[:5]:
            source = str(cite.get("source", "")).encode("ascii", "replace").decode()
            url = str(cite.get("url", ""))
            pdf.multi_cell(0, 4, f"- {source}: {url}", new_x="LMARGIN", new_y="NEXT")

    # -- Generate timestamp --
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(140, 140, 140)
    pdf.cell(0, 5, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())
