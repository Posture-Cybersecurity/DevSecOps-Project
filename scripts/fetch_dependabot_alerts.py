
import requests
import os
import csv
import sys

# ===== CONFIG =====
# Read GitHub token from environment (set in CI)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
OWNER = "Posture-Cybersecurity"
REPO = "maxone-vehicle-service"
OUTPUT_FILE = "DevSecOps-Demo.csv"

# Severities we care about
SEVERITIES = {"critical", "high", "medium"}

# GitHub API endpoint for Dependabot alerts
API_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/dependabot/alerts"


def fetch_dependabot_alerts():
    if not GITHUB_TOKEN:
        print("❌ GITHUB_TOKEN not set. Provide it via environment (e.g., GitHub Actions secret).")
        sys.exit(1)

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    page = 1
    alerts = []

    while True:
        params = {"per_page": 100, "page": page}
        response = requests.get(API_URL, headers=headers, params=params)

        if response.status_code != 200:
            print(f"❌ Failed to fetch alerts. Status: {response.status_code}")
            print(response.json())
            sys.exit(1)

        data = response.json()
        if not data:
            break

        alerts.extend(data)
        page += 1

    return alerts


def filter_alerts(alerts):
    filtered = []
    for alert in alerts:
        severity = alert.get("security_advisory", {}).get("severity", "").lower()
        state = alert.get("state", "").lower()

        if state == "open" and severity in SEVERITIES:
            filtered.append({
                "number": alert.get("number"),
                "package": alert.get("dependency", {}).get("package", {}).get("name"),
                "severity": severity,
                "state": state,
                "dependency_scope": alert.get("dependency", {}).get("scope"),
                "created_at": alert.get("created_at"),
                "url": alert.get("html_url"),
            })
    return filtered


def save_to_csv(alerts, filename):
    fieldnames = ["number", "package", "severity", "state", "dependency_scope", "created_at", "url"]

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)


if __name__ == "__main__":
    all_alerts = fetch_dependabot_alerts()
    filtered_alerts = filter_alerts(all_alerts)

    if filtered_alerts:
        print(f"❌ Found {len(filtered_alerts)} open critical/high/medium alerts")
        save_to_csv(filtered_alerts, OUTPUT_FILE)
        sys.exit(1)  # Fail the pipeline
    else:
        print("✅ No critical/high/medium open alerts found")
        sys.exit(0)
