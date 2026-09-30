import requests



def search_cves(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }

    print(f"Searching NVD for: {keyword}")

    response = requests.get(url, params=params, timeout=30)

    if response.status_code != 200:
        print("NVD API request failed.")
        print("Status code:", response.status_code)
        return

    data = response.json()

    print(f"\nTotal matching CVEs: {data.get('totalResults', 0)}")

    for item in data.get("vulnerabilities", []):

        cve = item.get("cve", {})

        cve_id = cve.get("id", "Unknown")

        description = "No description available."

        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        print("\n" + "-" * 60)
        print("CVE:", cve_id)
        print("Description:", description[:300])


if __name__ == "__main__":
    search_cves("OpenSSH")
