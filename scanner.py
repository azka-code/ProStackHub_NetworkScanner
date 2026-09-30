import nmap
import json
import os
import sys
from datetime import datetime

scanner = nmap.PortScanner()

OUTPUT_FILE = "data/scan_results.json"

os.makedirs("data", exist_ok=True)


def run_scan(target):

    print("=" * 55)
    print("PROSTACKHUB NETWORK VULNERABILITY SCANNER")
    print("=" * 55)

    print(f"\nTarget: {target}")
    print("Starting scan...\n")

    try:
        scanner.scan(target, arguments="-sV")

    except Exception as error:
        print("Nmap scan failed.")
        print("Error:", error)

        return {
            "target": target,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host_state": "error",
            "ports": []
        }

    results = {
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host_state": "unknown",
        "ports": []
    }

    if target not in scanner.all_hosts():

        print("Target was not found.")

        return results

    results["host_state"] = scanner[target].state()

    print(f"Host State: {results['host_state']}")

    for protocol in scanner[target].all_protocols():

        for port in sorted(scanner[target][protocol].keys()):

            service = scanner[target][protocol][port]

            port_data = {
                "port": port,
                "protocol": protocol,
                "state": service.get("state", "unknown"),
                "service": service.get("name", "unknown"),
                "product": service.get("product", "unknown"),
                "version": service.get("version", "unknown")
            }

            results["ports"].append(port_data)

            print(f"\nPort: {port}")
            print(f"Protocol: {protocol}")
            print(f"State: {port_data['state']}")
            print(f"Service: {port_data['service']}")
            print(f"Product: {port_data['product']}")
            print(f"Version: {port_data['version']}")

    return results


if __name__ == "__main__":

    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = "127.0.0.1"

    scan_results = run_scan(TARGET)

    with open(OUTPUT_FILE, "w") as file:
        json.dump(scan_results, file, indent=4)

    print("\n" + "=" * 55)
    print("Scan completed.")
    print(f"Results saved to: {OUTPUT_FILE}")
    print("=" * 55)
