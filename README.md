# ProStackHub Network Vulnerability Scanner

A Python-based Network Vulnerability Scanner developed as part of the ProStackHub Cyber Security Internship.

The project performs network scanning, service/version detection, NVD-based CVE lookup, CVSS-based risk classification, remediation guidance, PDF report generation, and provides a Flask web dashboard.

## Features

- Live host and network service scanning using Nmap
- Open port detection
- Service and version detection
- NVD/CVE vulnerability lookup
- CVSS-based risk classification
- Risk severity categories:
  - Critical
  - High
  - Medium
  - Low
- Automated remediation recommendations
- Professional PDF vulnerability assessment report
- Flask-based web dashboard
- JSON-based scan and assessment results
- Local authorized lab testing

## Technologies Used

- Python 3
- Nmap
- python-nmap
- Flask
- Requests
- NVD CVE API
- CVSS
- ReportLab
- HTML/CSS
- JSON

## Project Structure

```text
ProStackHub_NetworkScanner/
│
├── app.py
├── scanner.py
├── nvd_lookup.py
├── cve_scanner.py
├── risk_engine.py
├── remediation.py
├── report_generator.py
├── requirements.txt
├── .gitignore
│
├── templates/
│   └── dashboard.html
│
├── data/
│   ├── scan_results.json
│   ├── vulnerabilities.json
│   ├── risk_assessment.json
│   └── final_findings.json
│
└── reports/
    └── vulnerability_assessment_report.pdf
