"""PDF report generation."""

from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from dns_analyzer.dns_parsing import format_flags

MARGIN_LEFT = 50
MARGIN_TOP = 750
LINE_SPACING = 20


def generate_pdf_report(records: List[Dict[str, Any]], report_file: str) -> None:
    """Render the final, fully-annotated records to a PDF report."""
    c = canvas.Canvas(report_file, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(300, 770, "DNS Traffic Analysis Report")
    c.setFont("Helvetica", 12)
    y_position = MARGIN_TOP

    for record in records:
        formatted_flags = format_flags(record["flags"])
        flag_lines = formatted_flags.split("\n")
        z_score_text = (
            f"{record['entropy_z_score']:.2f}" if record["entropy_z_score"] is not None else "N/A"
        )

        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN_LEFT, y_position, f"Query: {record['query']}")
        c.setFont("Helvetica", 12)
        c.drawString(
            MARGIN_LEFT,
            y_position - LINE_SPACING,
            f"Source: {record['source_ip']} -> Destination: {record['destination_ip']}",
        )
        c.drawString(
            MARGIN_LEFT,
            y_position - 2 * LINE_SPACING,
            f"Entropy: {record['entropy']:.4f} (z-score: {z_score_text})",
        )
        c.drawString(MARGIN_LEFT, y_position - 3 * LINE_SPACING, "Flags:")
        for i, line in enumerate(flag_lines):
            c.drawString(MARGIN_LEFT + 20, y_position - (4 + i) * LINE_SPACING, line)
        c.setFillColor(colors.red)
        c.drawString(
            MARGIN_LEFT,
            y_position - (5 + len(flag_lines)) * LINE_SPACING,
            f"Remark: {record['remark']}",
        )
        c.setFillColor(colors.black)
        c.drawString(
            MARGIN_LEFT,
            y_position - (6 + len(flag_lines)) * LINE_SPACING,
            "-------------------------------------------------",
        )
        y_position -= 140 + (len(flag_lines) * LINE_SPACING)
        if y_position < 100:
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = MARGIN_TOP

    c.save()
