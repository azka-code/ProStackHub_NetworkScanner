import json
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

INPUT_FILE = "data/final_findings.json"
SCAN_FILE = "data/scan_results.json"
OUTPUT_FILE = "reports/vulnerability_assessment_report.pdf"


def load_json(filename):
    if not os.path.exists(filename):
        return {}

    with open(filename, "r") as file:
        return json.load(file)


def generate_report():

    data = load_json(INPUT_FILE)
    scan_data = load_json(SCAN_FILE)

    target = data.get("target", "Unknown")
    scan_time = data.get("scan_time", "Unknown")
    findings = data.get("findings", [])

    document = SimpleDocTemplate(
        OUTPUT_FILE,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=15,
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    )

    story = []

    # Title
    story.append(
        Paragraph(
            "Network Vulnerability Assessment Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            "ProStackHub Cyber Security Internship — Task 2",
            styles["Heading3"]
        )
    )

    story.append(Spacer(1, 20))

    # Executive information
    story.append(
        Paragraph(
            "Assessment Information",
            heading_style
        )
    )

    info_data = [
        ["Target", target],
        ["Scan Time", scan_time],
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Scanner", "Nmap + Python"],
        ["Vulnerability Database", "NVD"],
        ["Risk Assessment", "CVSS-based"],
    ]

    info_table = Table(info_data, colWidths=[150, 350])

    info_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(info_table)

    # Executive Summary
    story.append(
        Paragraph(
            "Executive Summary",
            heading_style
        )
    )

    summary_text = (
        f"The vulnerability assessment was performed against the authorized "
        f"target <b>{target}</b>. The assessment used Nmap for service and "
        f"port discovery and the National Vulnerability Database (NVD) for "
        f"CVE lookup. A total of "
        f"<b>{len(scan_data.get('ports', []))}</b> detected service/port "
        f"entries and <b>{len(findings)}</b> CVE findings were recorded."
    )

    story.append(
        Paragraph(summary_text, normal_style)
    )

    # Detected services
    story.append(
        Paragraph(
            "Detected Services and Open Ports",
            heading_style
        )
    )

    ports = scan_data.get("ports", [])

    if ports:

        port_table_data = [
            [
                "Port",
                "Protocol",
                "State",
                "Service",
                "Product",
                "Version"
            ]
        ]

        for port in ports:
            port_table_data.append([
                str(port.get("port", "")),
                str(port.get("protocol", "")),
                str(port.get("state", "")),
                str(port.get("service", "")),
                str(port.get("product", "")),
                str(port.get("version", ""))
            ])

        port_table = Table(
            port_table_data,
            repeatRows=1,
            colWidths=[45, 55, 55, 75, 100, 120]
        )

        port_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ])
        )

        story.append(port_table)

    else:

        story.append(
            Paragraph(
                "No open ports were detected.",
                normal_style
            )
        )

    # Vulnerability Findings
    story.append(
        Paragraph(
            "Vulnerability Findings",
            heading_style
        )
    )

    if findings:

        for index, finding in enumerate(findings, start=1):

            story.append(
                Paragraph(
                    f"Finding {index}: {finding.get('cve_id', 'Unknown')}",
                    styles["Heading3"]
                )
            )

            finding_data = [
                ["Port", str(finding.get("port", "N/A"))],
                ["Service", str(finding.get("service", "N/A"))],
                ["Product", str(finding.get("product", "N/A"))],
                ["Version", str(finding.get("version", "N/A"))],
                ["CVSS Score", str(finding.get("cvss_score", "N/A"))],
                ["Severity", str(finding.get("severity", "Unknown"))],
                ["Risk Level", str(finding.get("risk_level", "Unknown"))],
            ]

            finding_table = Table(
                finding_data,
                colWidths=[120, 380]
            )

            finding_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ])
            )

            story.append(finding_table)
            story.append(Spacer(1, 8))

            story.append(
                Paragraph(
                    "<b>Description:</b> " +
                    str(finding.get("description", "No description available.")),
                    normal_style
                )
            )

            story.append(Spacer(1, 8))

            story.append(
                Paragraph(
                    "<b>Recommended Remediation:</b> " +
                    str(
                        finding.get(
                            "remediation",
                            "Review the affected service and apply vendor security updates."
                        )
                    ),
                    normal_style
                )
            )

            story.append(Spacer(1, 15))

    else:

        story.append(
            Paragraph(
                "No CVE-based vulnerabilities were identified during this assessment.",
                normal_style
            )
        )

        story.append(
            Paragraph(
                "This result means that the current NVD keyword lookup did "
                "not return matching CVE records. It does not establish that "
                "the target is completely free of security weaknesses.",
                normal_style
            )
        )

    # Conclusion
    story.append(
        Paragraph(
            "Assessment Conclusion",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "The assessment identified the network services exposed by the "
            "authorized target and compared detected software information "
            "against NVD vulnerability data. Administrators should keep "
            "software patched, remove unnecessary services, and restrict "
            "network exposure according to the system's operational "
            "requirements.",
            normal_style
        )
    )

    document.build(story)

    print("=" * 60)
    print("PDF REPORT GENERATED")
    print("=" * 60)
    print(f"Report: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_report()
