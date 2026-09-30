import json
import os

INPUT_FILE = "data/risk_assessment.json"
OUTPUT_FILE = "data/final_findings.json"


def get_remediation(finding):

    service = str(finding.get("service", "")).lower()
    product = str(finding.get("product", "")).lower()
    risk = finding.get("risk_level", "Unknown")

    if risk in ["Critical", "High"]:
        return (
            "Prioritize remediation immediately. "
            "Update the affected software to a supported patched version, "
            "verify vendor security advisories, and restrict unnecessary "
            "network exposure until remediation is complete."
        )

    if risk == "Medium":
        return (
            "Update the affected service to the latest supported version, "
            "review its configuration, and restrict access to trusted hosts "
            "where possible."
        )

    if risk == "Low":
        return (
            "Review the service configuration and keep the software updated. "
            "Disable the service if it is not required."
        )

    if "http" in service or "http" in product:
        return (
            "Use a properly configured production web server for production "
            "systems. Restrict unnecessary network access and keep the "
            "underlying software updated."
        )

    return (
        "No specific CVE-based remediation was identified. "
        "Keep the service updated, review its configuration, and disable "
        "unnecessary network exposure."
    )


def main():

    if not os.path.exists(INPUT_FILE):
        print("Risk assessment file not found.")
        return

    with open(INPUT_FILE, "r") as file:
        data = json.load(file)

    final_results = {
        "target": data.get("target"),
        "scan_time": data.get("scan_time"),
        "findings": []
    }

    for finding in data.get("findings", []):

        finding["remediation"] = get_remediation(finding)

        final_results["findings"].append(finding)

    with open(OUTPUT_FILE, "w") as file:
        json.dump(final_results, file, indent=4)

    print("=" * 60)
    print("REMEDIATION ANALYSIS COMPLETED")
    print("=" * 60)
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
