from flask import Flask, render_template, request, redirect, url_for, send_file
import subprocess
import json
import os

app = Flask(__name__)

SCAN_FILE = "data/scan_results.json"
VULN_FILE = "data/vulnerabilities.json"
RISK_FILE = "data/risk_assessment.json"
FINAL_FILE = "data/final_findings.json"
REPORT_FILE = "reports/vulnerability_assessment_report.pdf"


def load_json(filename):

    if not os.path.exists(filename):
        return {}

    with open(filename, "r") as file:
        return json.load(file)


@app.route("/")
def dashboard():

    scan_data = load_json(SCAN_FILE)
    vuln_data = load_json(VULN_FILE)
    risk_data = load_json(RISK_FILE)
    final_data = load_json(FINAL_FILE)

    vulnerabilities = final_data.get(
        "findings",
        vuln_data.get("vulnerabilities", [])
    )

    return render_template(
        "dashboard.html",
        scan=scan_data,
        vulnerabilities=vulnerabilities,
        risk=risk_data
    )


@app.route("/scan", methods=["POST"])
def start_scan():

    target = request.form.get("target", "").strip()

    if not target:
        return redirect(url_for("dashboard"))

    # Local lab target for this internship project
    if target != "127.0.0.1":
        return redirect(url_for("dashboard"))

    print(f"\nStarting scan for: {target}")

    subprocess.run(
        ["python3", "scanner.py", target],
        check=False
    )

    subprocess.run(
        ["python3", "nvd_lookup.py"],
        check=False
    )

    subprocess.run(
        ["python3", "risk_engine.py"],
        check=False
    )

    subprocess.run(
        ["python3", "remediation.py"],
        check=False
    )

    subprocess.run(
        ["python3", "report_generator.py"],
        check=False
    )

    print("Complete scan workflow finished.")

    return redirect(url_for("dashboard"))


@app.route("/generate-report")
def generate_report():

    subprocess.run(
        ["python3", "report_generator.py"],
        check=False
    )

    if not os.path.exists(REPORT_FILE):
        return "Report generation failed.", 500

    return send_file(
        REPORT_FILE,
        as_attachment=False,
        mimetype="application/pdf"
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
