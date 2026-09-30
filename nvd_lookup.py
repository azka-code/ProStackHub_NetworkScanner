import json
import requests
import time
import os

SCAN_FILE = "data/scan_results.json"
OUTPUT_FILE = "data/vulnerabilities.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_nvd(keyword):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 10
    }

    try:
        response = requests.get(
            NVD_URL,
            params=params,
            timeout=30
        )

        if response.status_code != 200:
            print(f"NVD request failed for {keyword}")
            print("Status:", response.status_code)
            return []

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get("id", "Unknown")

            description = "No description available."

            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break

            cvss_score = None
            severity = "Unknown"

            metrics = cve.get("metrics", {})

            for metric_name in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]:

                if metric_name in metrics and metrics[metric_name]:

                    metric = metrics[metric_name][0]
                    cvss_data = metric.get("cvssData", {})

                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "Unknown")

                    break

            vulnerabilities.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity
            })

        return vulnerabilities

    except requests.RequestException as error:
        print("Network error:", error)
        return []


def main():

    if not os.path.exists(SCAN_FILE):
        print("Scan results file not found.")
        return

    with open(SCAN_FILE, "r") as file:
        scan_data = json.load(file)

    final_results = {
        "target": scan_data.get("target"),
        "scan_time": scan_data.get("scan_time"),
        "vulnerabilities": []
    }

    for port in scan_data.get("ports", []):

        service = port.get("service", "")
        product = port.get("product", "")
        version = port.get("version", "")

        keyword_parts = []

        if product and product != "unknown":
            keyword_parts.append(product)

        if service and service != "unknown":
            keyword_parts.append(service)

        if version and version != "unknown":
            keyword_parts.append(version)

        keyword = " ".join(keyword_parts).strip()

        if not keyword:
            continue

        print("\n" + "=" * 60)
        print("Checking:", keyword)
        print("=" * 60)

        cves = search_nvd(keyword)

        for cve in cves:

            final_results["vulnerabilities"].append({
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "service": service,
                "product": product,
                "version": version,
                "keyword": keyword,
                "cve_id": cve["cve_id"],
                "description": cve["description"],
                "cvss_score": cve["cvss_score"],
                "severity": cve["severity"]
            })

        # Small delay between requests
        time.sleep(1)

    with open(OUTPUT_FILE, "w") as file:
        json.dump(final_results, file, indent=4)

    print("\n" + "=" * 60)
    print("NVD vulnerability lookup completed.")
    print(f"Results saved to: {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()

