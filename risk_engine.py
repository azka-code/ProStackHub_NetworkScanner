import json
import os

INPUT_FILE = "data/vulnerabilities.json"
OUTPUT_FILE = "data/risk_assessment.json"


def classify_risk(score):
    if score is None:
        return "Unknown"

    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "None"


def main():

    if not os.path.exists(INPUT_FILE):
        print("Vulnerability file not found.")
        return

    with open(INPUT_FILE, "r") as file:
        data = json.load(file)

    results = {
        "target": data.get("target"),
        "scan_time": data.get("scan_time"),
        "risk_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        },
        "findings": []
    }

    for vulnerability in data.get("vulnerabilities", []):

        score = vulnerability.get("cvss_score")

        risk = classify_risk(score)

        if risk == "Critical":
            results["risk_summary"]["critical"] += 1
        elif risk == "High":
            results["risk_summary"]["high"] += 1
        elif risk == "Medium":
            results["risk_summary"]["medium"] += 1
        elif risk == "Low":
            results["risk_summary"]["low"] += 1
        else:
            results["risk_summary"]["unknown"] += 1

        finding = {
            "port": vulnerability.get("port"),
            "service": vulnerability.get("service"),
            "product": vulnerability.get("product"),
            "version": vulnerability.get("version"),
            "cve_id": vulnerability.get("cve_id"),
            "cvss_score": score,
            "severity": vulnerability.get("severity"),
            "risk_level": risk,
            "description": vulnerability.get("description")
        }

        results["findings"].append(finding)

    with open(OUTPUT_FILE, "w") as file:
        json.dump(results, file, indent=4)

    print("=" * 60)
    print("RISK ASSESSMENT COMPLETED")
    print("=" * 60)

    print("\nRisk Summary:")

    for level, count in results["risk_summary"].items():
        print(f"{level.capitalize()}: {count}")

    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
