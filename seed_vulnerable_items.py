"""
Seed Chrome / Edge vulnerabilities into ServiceNow Vulnerability Response.

Creates real vulnerability definitions (sn_vul_third_party_entry) and links
vulnerable items (sn_vul_vulnerable_item) to them, so the "Vulnerability"
column is filled in and the agent can recognise Chrome / Edge findings.

Usage:
    python seed_vulnerable_items.py --dry-run   # preview
    python seed_vulnerable_items.py             # create
    python seed_vulnerable_items.py --delete    # remove everything this script created
"""

import argparse
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

DEMO_MARKER = "AGENT-POC-VIT-DEMO"
GROUP_NAME  = "S-TCS-DC-WINTEL"

# Vulnerability definitions (one per software issue)
ENTRIES = {
    "chrome": {
        "id":      "QID-CHROME-V8-2024",
        "name":    "Google Chrome V8 Type Confusion Remote Code Execution",
        "summary": "Google Chrome prior to 126.0.6478.126 allows a remote attacker to execute "
                   "arbitrary code via a crafted HTML page (V8 type confusion).",
    },
    "edge": {
        "id":      "QID-EDGE-CHROMIUM-2024",
        "name":    "Microsoft Edge Chromium Use-After-Free Remote Code Execution",
        "summary": "Microsoft Edge (Chromium-based) prior to 126.0.2592.87 is affected by a "
                   "use-after-free that can lead to remote code execution.",
    },
}

# Vulnerable items: one or more per simulated server node
ITEMS = [
    # node_1 — WINTEL-SERVER-01
    {"entry": "chrome", "ci": "ppwischwaapg003", "risk_score": 95,
     "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe 124.0.6367.91"},
    {"entry": "edge",   "ci": "pvwiihamwaapg110", "risk_score": 88,
     "path": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe 124.0.2478.80"},
    # node_2 — WINTEL-SERVER-02
    {"entry": "edge",   "ci": "pvwidc1tccxg054", "risk_score": 92,
     "path": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe 123.0.2420.97"},
    {"entry": "chrome", "ci": "pvwidc1tccxg037", "risk_score": 76,
     "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe 125.0.6422.60"},
    # node_3 — WINTEL-SERVER-03
    {"entry": "chrome", "ci": "pvwihamifcxg028", "risk_score": 97,
     "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe 122.0.6261.94"},
    {"entry": "edge",   "ci": "pvwihamifcxg027", "risk_score": 84,
     "path": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe 125.0.2535.51"},
]


class Seeder:
    def __init__(self, url, user, pwd):
        self.base = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (user, pwd)
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def _get(self, table, query, fields="sys_id"):
        r = self.s.get(f"{self.base}/api/now/table/{table}",
                       params={"sysparm_query": query, "sysparm_fields": fields, "sysparm_limit": 100},
                       timeout=30)
        r.raise_for_status()
        return r.json()["result"]

    def _post(self, table, body):
        r = self.s.post(f"{self.base}/api/now/table/{table}", json=body, timeout=30)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"{table}: HTTP {r.status_code} {r.text[:300]}")
        return r.json()["result"]

    def _delete(self, table, sys_id):
        return self.s.delete(f"{self.base}/api/now/table/{table}/{sys_id}", timeout=30).status_code

    def lookup(self, table, field, value):
        rows = self._get(table, f"{field}={value}")
        return rows[0]["sys_id"] if rows else None

    def ensure_ci(self, name):
        return self.lookup("cmdb_ci", "name", name) or \
            self._post("cmdb_ci_server", {"name": name, "short_description": f"Target Server {name}"})["sys_id"]

    def ensure_entry(self, e):
        """Return the vulnerability definition's sys_id, or None if the instance won't let us create it.

        Vulnerability definitions normally arrive via a scanner integration (Qualys etc.) and
        most instances block REST inserts with an ACL. Items still work without the link —
        the agent reads the software name from the item's description.
        """
        existing = self.lookup("sn_vul_third_party_entry", "id", e["id"])
        if existing:
            return existing
        try:
            return self._post("sn_vul_third_party_entry", {
                "id": e["id"], "name": e["name"], "summary": e["summary"],
                "description": f"{e['summary']}\nMarker: {DEMO_MARKER}",
            })["sys_id"]
        except RuntimeError as err:
            if "403" not in str(err):
                raise
            return None

    def seed(self, dry_run):
        group = self.lookup("sys_user_group", "name", GROUP_NAME)
        if not group:
            sys.exit(f"Assignment group {GROUP_NAME} not found — run seed_servicenow.py first.")

        entry_ids = {}
        for key, e in ENTRIES.items():
            if dry_run:
                print(f"  WOULD CREATE vulnerability {e['id']} — {e['name']}")
            else:
                entry_ids[key] = self.ensure_entry(e)
                print(f"  Vulnerability {e['id']} " + ("ready" if entry_ids[key] else
                      "not linkable (ACL blocks creating definitions) — items carry it in the description"))

        for it in ITEMS:
            e = ENTRIES[it["entry"]]
            if dry_run:
                print(f"  WOULD CREATE item on {it['ci']:<18} {e['name'][:45]} (score {it['risk_score']})")
                continue
            body = {
                "cmdb_ci":          self.ensure_ci(it["ci"]),
                "assignment_group": group,
                "state":            "1",
                "risk_score":       str(it["risk_score"]),
                # risk_score is recalculated by ServiceNow (0 without a linked vulnerability),
                # so the description carries the intended score for the agent to read.
                "description":      f"{it['path']}\nSummary: {e['name']}\nQID: {e['id']}\n"
                                    f"Risk Score: {it['risk_score']}\nMarker: {DEMO_MARKER}",
            }
            if entry_ids[it["entry"]]:
                body["vulnerability"] = entry_ids[it["entry"]]
            vit = self._post("sn_vul_vulnerable_item", body)
            print(f"  Created {vit.get('number')} on {it['ci']:<18} {e['name'][:45]}")

    def delete(self):
        n = 0
        for row in self._get("sn_vul_vulnerable_item", f"descriptionLIKE{DEMO_MARKER}", "sys_id,number"):
            print(f"  Deleting {row['number']} -> HTTP {self._delete('sn_vul_vulnerable_item', row['sys_id'])}")
            n += 1
        for e in ENTRIES.values():
            sid = self.lookup("sn_vul_third_party_entry", "id", e["id"])
            if sid:
                print(f"  Deleting vulnerability {e['id']} -> HTTP {self._delete('sn_vul_third_party_entry', sid)}")
                n += 1
        print(f"  Removed {n} records.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--delete", action="store_true")
    args = p.parse_args()

    url, user, pwd = (os.getenv(k, "") for k in
                      ("SERVICENOW_INSTANCE_URL", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD"))
    if not (url and user and pwd):
        sys.exit("Set SERVICENOW_INSTANCE_URL / USERNAME / PASSWORD in .env")

    s = Seeder(url, user, pwd)
    s.delete() if args.delete else s.seed(args.dry_run)


if __name__ == "__main__":
    main()
