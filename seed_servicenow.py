"""
ServiceNow Demo Data Seeder
════════════════════════════════════════════════════════════════════

Seeds realistic vulnerability records into ServiceNow's
sn_vul_m2m_vul_group_item table — exactly matching the data
visible in your screenshots (same server names, QIDs, risk scores,
assignment groups as in the real Qualys export).

Usage:
    python seed_servicenow.py --dry-run          # Preview what will be created
    python seed_servicenow.py                    # Actually POST to ServiceNow
    python seed_servicenow.py --delete-demo      # Remove previously seeded records

Requirements:
    Set in .env or pass as args:
        SERVICENOW_INSTANCE_URL = https://yourinstance.service-now.com
        SERVICENOW_USERNAME     = admin
        SERVICENOW_PASSWORD     = yourpassword

What this creates:
    • 15 vulnerability remediation task item records
    • Spread across 3 batches (June Cyber, August Cyber, October Cyber)
    • Mix of Critical / High / Moderate risk
    • Covers: 7-Zip, MS Edge, MS Office, Windows DLL, Adobe, Chrome
    • Matching exact server CI names from your environment screenshots
    • All tagged with a demo marker so they can be cleanly removed later
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
#  TARGET TABLE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_TABLE = "sn_vul_m2m_vul_group_item"

# Marker so we can find & delete seeded records later
DEMO_MARKER = "AGENT-POC-DEMO"

# ─────────────────────────────────────────────────────────────────────────────
#  SEED DATA  — mirrors exactly what appears in your ServiceNow screenshots
#  Server names taken from the Servers list screenshot (PV\Vipin view)
# ─────────────────────────────────────────────────────────────────────────────
SEED_RECORDS: List[Dict[str, Any]] = [

    # ── BATCH 1: June Cyber Prioritization ─────────────────────────────────
    {
        "short_description":    "June Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "ppwischwaapg003",          # from screenshot row 1
        "remediation_task":     "VUL0010165",
        "vulnerable_item":      "VIT1463963",
        "description":          "C:\\Program Files\\7-Zip\\7z.exe Version 19.00",
        "summary":              "7-Zip Mark-of-the-Web Bypass Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",                        # 3 - Non-critical
        "risk_rating":          "1",                        # 1 - Critical
        "risk_score":           "95",
        "u_qid":                "QID-382694",
        "state":                "1",                        # 1 = Open in ServiceNow
        "u_percent_remediated": "73.50",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "June Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "evwidc4lfgic225",          # from screenshot row 2
        "remediation_task":     "VUL0010165",
        "vulnerable_item":      "VIT0048765",
        "description":          "C:\\Program Files\\7-Zip\\7z.exe Version 19.00",
        "summary":              "7-Zip Mark-of-the-Web Bypass Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "95",
        "u_qid":                "QID-382694",
        "state":                "1",
        "u_percent_remediated": "73.50",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "June Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "ppwischwaapg004",          # from screenshot row 3
        "remediation_task":     "VUL0010165",
        "vulnerable_item":      "VIT1464789",
        "description":          "C:\\Program Files\\7-Zip\\7z.exe Version 21.03",
        "summary":              "7-Zip Mark-of-the-Web Bypass Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "95",
        "u_qid":                "QID-382694",
        "state":                "1",
        "u_percent_remediated": "73.50",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },

    # ── BATCH 2: August Cyber Prioritization ────────────────────────────────
    {
        "short_description":    "August Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwiihamwaapg110",         # from Excel screenshot
        "remediation_task":     "VUL0010533",
        "vulnerable_item":      "VIT0053861",
        "description":          "C:\\Program Files\\7-Zip\\7z.exe Version 19.00",
        "summary":              "7-Zip Mark-of-the-Web Bypass Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "95",
        "u_qid":                "QID-382694",
        "state":                "1",
        "u_percent_remediated": "90.63",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "August Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwidc1tccxg037",
        "remediation_task":     "VUL0010541",
        "vulnerable_item":      "VIT5754720",
        "description":          "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe 114.0.1823.58",
        "summary":              "Microsoft Edge Chromium Elevation of Privilege & RCE Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "95",
        "u_qid":                "QID-377887",
        "state":                "1",
        "u_percent_remediated": "55.76",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "August Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwihamifcxg029",
        "remediation_task":     "VUL0010533",
        "vulnerable_item":      "VIT0020029",
        "description":          "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe 113.0.1774.57",
        "summary":              "Microsoft Edge Chromium Elevation of Privilege & RCE Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "95",
        "u_qid":                "QID-377887",
        "state":                "1",
        "u_percent_remediated": "55.76",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "August Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwidc1tccxg054",
        "remediation_task":     "VUL0010533",
        "vulnerable_item":      "VIT7116080",
        "description":          "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE 16.0.14332.20604",
        "summary":              "Microsoft Office / 365 Remote Code Execution (CVE-2023-23397)",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "2",                        # 2 - Significant
        "risk_rating":          "1",
        "risk_score":           "98",
        "u_qid":                "QID-378388",
        "state":                "1",
        "u_percent_remediated": "16.18",
        "u_source_severity":    "5",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "August Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwihamifcxg031",
        "remediation_task":     "VUL0010533",
        "vulnerable_item":      "VIT1684582",
        "description":          "C:\\Windows\\System32\\ntoskrnl.exe (Windows Kernel)",
        "summary":              "Microsoft Windows DLL Hijacking / Kernel Privilege Escalation",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "1",                        # 1 - Critical
        "risk_rating":          "1",
        "risk_score":           "99",
        "u_qid":                "QID-380476",
        "state":                "1",
        "u_percent_remediated": "16.18",
        "u_source_severity":    "5",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "August Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwihamifcxg028",
        "remediation_task":     "VUL0010533",
        "vulnerable_item":      "VIT0020378",
        "description":          "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe 23.001.20093",
        "summary":              "Adobe Acrobat Reader Arbitrary Code Execution Vulnerability",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "95",
        "u_qid":                "QID-383609",
        "state":                "1",
        "u_percent_remediated": "90.63",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },

    # ── BATCH 3: October Cyber Prioritization ───────────────────────────────
    {
        "short_description":    "October Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "PPEDC1FHVG166",            # from Servers list screenshot
        "remediation_task":     "VUL0010695",
        "vulnerable_item":      "VIT5748723",
        "description":          "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe 114.0.5735.110",
        "summary":              "Google Chrome V8 Type Confusion Remote Code Execution",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "2",                        # 2 - High
        "risk_score":           "78",
        "u_qid":                "QID-362145",
        "state":                "1",
        "u_percent_remediated": "85.00",
        "u_source_severity":    "3",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "October Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "PPEDC1FHVG167",            # from Servers list screenshot
        "remediation_task":     "VUL0010695",
        "vulnerable_item":      "VIT7116081",
        "description":          "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE 16.0.14332.20604",
        "summary":              "Microsoft Excel Remote Code Execution (CVE-2023-36041)",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "2",
        "risk_rating":          "1",
        "risk_score":           "97",
        "u_qid":                "QID-379201",
        "state":                "1",
        "u_percent_remediated": "20.00",
        "u_source_severity":    "5",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "October Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "PPEDC2FHVG125",            # from Servers list screenshot
        "remediation_task":     "VUL0010695",
        "vulnerable_item":      "VIT1502606",
        "description":          "C:\\Windows\\System32\\win32kfull.sys (Win32k Driver)",
        "summary":              "Microsoft Windows Win32k Kernel Driver Privilege Escalation",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "1",
        "risk_rating":          "1",
        "risk_score":           "99",
        "u_qid":                "QID-381044",
        "state":                "1",
        "u_percent_remediated": "10.00",
        "u_source_severity":    "5",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "October Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "PPEDC3FHVG126",
        "remediation_task":     "VUL0010695",
        "vulnerable_item":      "VIT1178920",
        "description":          "C:\\Program Files\\Notepad++\\notepad++.exe 8.1.4",
        "summary":              "Notepad++ Heap Buffer Overflow / Remote Code Execution",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "4",                        # 4 - Minor
        "risk_rating":          "3",                        # 3 - Moderate
        "risk_score":           "45",
        "u_qid":                "QID-355120",
        "state":                "1",
        "u_percent_remediated": "73.50",
        "u_source_severity":    "2",
        "u_operating_env":      "Staging",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "October Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwihamifcxg027",
        "remediation_task":     "VUL0010695",
        "vulnerable_item":      "VIT0077477",
        "description":          "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe 115.0.1901.188",
        "summary":              "Microsoft Edge Chromium Use-After-Free Memory Corruption",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "1",
        "risk_score":           "93",
        "u_qid":                "QID-380201",
        "state":                "1",
        "u_percent_remediated": "62.00",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
    {
        "short_description":    "October Cyber Prioritization",
        "u_demo_marker":        DEMO_MARKER,
        "cmdb_ci":              "pvwidc1tccxg037",
        "remediation_task":     "VUL0010695",
        "vulnerable_item":      "VIT0054721",
        "description":          "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe 112.0.1722.48",
        "summary":              "Microsoft Edge Chromium Heap Buffer Overflow (CVE-2023-2136)",
        "assignment_group":     "S-TCS-DC-WINTEL",
        "business_impact":      "3",
        "risk_rating":          "2",
        "risk_score":           "80",
        "u_qid":                "QID-376540",
        "state":                "1",
        "u_percent_remediated": "78.00",
        "u_source_severity":    "4",
        "u_operating_env":      "Production",
        "operational_status":   "Operational",
        "work_notes":           f"[DEMO] Seeded by Vulnerability Remediation Agent POC ({DEMO_MARKER})"
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  SEEDER CLASS
# ─────────────────────────────────────────────────────────────────────────────
class ServiceNowSeeder:
    def __init__(self, instance_url: str, username: str, password: str, table: str = DEFAULT_TABLE):
        self.base_url = instance_url.rstrip("/")
        self.auth     = (username, password)
        self.headers  = {
            "Accept":       "application/json",
            "Content-Type": "application/json",
        }
        self.table = table
        self.table_url = f"{self.base_url}/api/now/table/{self.table}"
        self.group_sys_id = None
        self.ci_cache = {}

    def ensure_prerequisites(self):
        """Ensure assignment group S-TCS-DC-WINTEL exists and prepare CIs."""
        try:
            # Check or create group
            g_url = f"{self.base_url}/api/now/table/sys_user_group?sysparm_query=name=S-TCS-DC-WINTEL&sysparm_fields=sys_id"
            r = requests.get(g_url, auth=self.auth, headers=self.headers, timeout=10)
            if r.status_code == 200 and r.json().get("result"):
                self.group_sys_id = r.json()["result"][0]["sys_id"]
            else:
                cr = requests.post(
                    f"{self.base_url}/api/now/table/sys_user_group",
                    auth=self.auth, headers=self.headers,
                    json={"name": "S-TCS-DC-WINTEL", "description": "Windows Infrastructure & Server Operations Team"},
                    timeout=10
                )
                if cr.status_code in [200, 201]:
                    self.group_sys_id = cr.json().get("result", {}).get("sys_id")

            # Check or create CIs in cmdb_ci_server
            ci_names = set(r["cmdb_ci"] for r in SEED_RECORDS)
            for ci in ci_names:
                ci_check = requests.get(
                    f"{self.base_url}/api/now/table/cmdb_ci?sysparm_query=name={ci}&sysparm_fields=sys_id",
                    auth=self.auth, headers=self.headers, timeout=10
                )
                if ci_check.status_code == 200 and ci_check.json().get("result"):
                    self.ci_cache[ci] = ci_check.json()["result"][0]["sys_id"]
                else:
                    ci_cr = requests.post(
                        f"{self.base_url}/api/now/table/cmdb_ci_server",
                        auth=self.auth, headers=self.headers,
                        json={"name": ci, "short_description": f"Target Server {ci}"},
                        timeout=10
                    )
                    if ci_cr.status_code in [200, 201]:
                        self.ci_cache[ci] = ci_cr.json().get("result", {}).get("sys_id")
        except Exception as e:
            print(f"  Note during prerequisite setup: {e}")

    def test_connection(self) -> bool:
        """Quick connectivity check with table fallback."""
        print(f"  Testing connection to {self.base_url} ...")
        try:
            r = requests.get(
                f"{self.table_url}?sysparm_limit=1",
                auth=self.auth, headers=self.headers, timeout=10
            )
            if r.status_code == 200:
                print(f"  Connected. Table '{self.table}' is accessible.")
                return True
            elif r.status_code == 400 and self.table == DEFAULT_TABLE:
                print(f"  Table '{DEFAULT_TABLE}' not found on this instance. Switching automatically to 'incident' (Security/Vulnerability records)...")
                self.table = "incident"
                self.table_url = f"{self.base_url}/api/now/table/{self.table}"
                return True
            elif r.status_code == 401:
                print(f"  Authentication failed (401). Check username / password.")
            elif r.status_code == 403:
                print(f"  Forbidden (403). Your user may not have write access to {self.table}.")
            else:
                print(f"  HTTP {r.status_code}: {r.text[:200]}")
        except requests.exceptions.ConnectionError:
            print(f"  Cannot reach {self.base_url}. Check VPN / instance URL.")
        except Exception as e:
            print(f"  Error: {e}")
        return False

    def seed_records(self, dry_run: bool = False) -> List[str]:
        """POST each record into ServiceNow. Returns list of created sys_ids."""
        created_ids = []
        self.ensure_prerequisites()

        print(f"\n{'─'*60}")
        print(f"  {'[DRY RUN] PREVIEW' if dry_run else 'SEEDING'} — {len(SEED_RECORDS)} records → {self.table}")
        print(f"{'─'*60}")

        for i, record in enumerate(SEED_RECORDS, 1):
            ci    = record.get("cmdb_ci", "unknown")
            summ  = record.get("summary", "")[:55]
            batch = record.get("short_description", "")

            if dry_run:
                print(f"  [{i:02d}] WOULD CREATE: [{batch}] {ci} — {summ}")
                continue

            if self.table == "incident":
                payload = {
                    "short_description": f"Qualys Vulnerability: {batch} - {summ}",
                    "description": (
                        f"[QUALYS VULNERABILITY AUDIT]\n"
                        f"Task: {record.get('remediation_task')}\n"
                        f"Item: {record.get('vulnerable_item')}\n"
                        f"QID: {record.get('u_qid')}\n"
                        f"Summary: {record.get('summary')}\n"
                        f"Path/Version: {record.get('description')}\n"
                        f"Risk Score: {record.get('risk_score')} (Rating: {record.get('risk_rating')})\n"
                        f"Business Impact: {record.get('business_impact')}\n"
                        f"Server CI: {ci}\n"
                        f"Marker: {DEMO_MARKER}"
                    ),
                    "category": "security",
                    "urgency": "1" if int(record.get("risk_score", 0)) >= 80 else "2",
                    "impact": "1",
                    "priority": "1" if int(record.get("risk_score", 0)) >= 80 else "2",
                    "state": "1",  # New / Open
                    "comments": f"[DEMO QUALYS INGEST] {DEMO_MARKER} - Assignment: S-TCS-DC-WINTEL"
                }
                if self.group_sys_id:
                    payload["assignment_group"] = self.group_sys_id
                if ci in self.ci_cache:
                    payload["cmdb_ci"] = self.ci_cache[ci]
            else:
                payload = record

            try:
                r = requests.post(
                    self.table_url,
                    auth=self.auth,
                    headers=self.headers,
                    json=payload,
                    timeout=15,
                )
                if r.status_code in [200, 201]:
                    res_json = r.json().get("result", {})
                    sys_id = res_json.get("sys_id", "?")
                    num    = res_json.get("number", sys_id)
                    created_ids.append(sys_id)
                    print(f"  [{i:02d}] Created  [{num}] [{batch}] {ci} — {summ}")
                else:
                    print(f"  [{i:02d}] Failed   [{batch}] {ci} — HTTP {r.status_code}")
                    print(f"        Response: {r.text[:300]}")
                time.sleep(0.3)
            except Exception as e:
                print(f"  [{i:02d}] Error    {ci} — {e}")

        return created_ids

    def delete_demo_records(self) -> int:
        """Find and delete all records seeded by this tool (u_demo_marker = AGENT-POC-DEMO)."""
        print(f"\n{'─'*60}")
        print(f"  Searching for demo records (marker: {DEMO_MARKER}) ...")
        print(f"{'─'*60}")

        # Query for our marker field
        query_url = (
            f"{self.table_url}"
            f"?sysparm_query=u_demo_marker={DEMO_MARKER}"
            f"&sysparm_fields=sys_id,cmdb_ci,short_description"
            f"&sysparm_limit=100"
        )
        try:
            r = requests.get(query_url, auth=self.auth, headers=self.headers, timeout=10)
            if r.status_code != 200:
                print(f"  ❌ Search failed: HTTP {r.status_code}")
                return 0
            records = r.json().get("result", [])
        except Exception as e:
            print(f"  ❌ Search error: {e}")
            return 0

        if not records:
            print(f"  ℹ  No demo records found to delete.")
            return 0

        print(f"  Found {len(records)} demo records. Deleting...")
        deleted = 0
        for rec in records:
            sys_id = rec.get("sys_id")
            ci     = rec.get("cmdb_ci", {})
            ci_name = ci.get("display_value", ci) if isinstance(ci, dict) else ci
            try:
                dr = requests.delete(
                    f"{self.table_url}/{sys_id}",
                    auth=self.auth, headers=self.headers, timeout=10
                )
                if dr.status_code == 204:
                    print(f"  🗑  Deleted  {ci_name} ({sys_id})")
                    deleted += 1
                else:
                    print(f"  ❌  Failed   {ci_name} ({sys_id}) — HTTP {dr.status_code}")
                time.sleep(0.2)
            except Exception as e:
                print(f"  ❌  Error deleting {sys_id}: {e}")

        return deleted

    def save_created_ids(self, ids: List[str]):
        """Save created sys_ids locally so we can delete them later."""
        path = os.path.join(os.path.dirname(__file__), "seeded_ids.json")
        with open(path, "w") as f:
            json.dump({"seeded_sys_ids": ids, "marker": DEMO_MARKER}, f, indent=2)
        print(f"\n  💾 Saved {len(ids)} sys_ids to seeded_ids.json (use --delete-demo to remove them)")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Seed demo vulnerability data into ServiceNow for the Remediation Agent POC"
    )
    parser.add_argument("--instance-url", default=os.getenv("SERVICENOW_INSTANCE_URL", ""),
                        help="ServiceNow instance URL (or set SERVICENOW_INSTANCE_URL in .env)")
    parser.add_argument("--username", default=os.getenv("SERVICENOW_USERNAME", ""),
                        help="ServiceNow username (or set SERVICENOW_USERNAME in .env)")
    parser.add_argument("--password", default=os.getenv("SERVICENOW_PASSWORD", ""),
                        help="ServiceNow password (or set SERVICENOW_PASSWORD in .env)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview records without actually POSTing to ServiceNow")
    parser.add_argument("--delete-demo", action="store_true",
                        help="Delete all previously seeded demo records from ServiceNow")
    args = parser.parse_args()

    print()
    print("=" * 62)
    print("  ServiceNow Demo Data Seeder -- Vulnerability Agent POC")
    print("=" * 62)
    print(f"  Target   : {DEFAULT_TABLE} (auto-fallback to incident if not installed)")
    print(f"  Records  : {len(SEED_RECORDS)} vulnerability items")
    print(f"  Batches  : June / August / October Cyber Prioritization")
    print(f"  Servers  : {len(set(r['cmdb_ci'] for r in SEED_RECORDS))} unique CIs")
    print()

    if not args.instance_url or not args.username or not args.password:
        if not args.dry_run:
            print("  [ERROR] Missing credentials. Either:")
            print("     1. Fill in SERVICENOW_INSTANCE_URL / USERNAME / PASSWORD in your .env file")
            print("     2. Pass them as --instance-url / --username / --password arguments")
            print("     3. Run with --dry-run to preview without needing credentials")
            sys.exit(1)

    if args.dry_run:
        print("  [DRY RUN] Preview only -- nothing will be written to ServiceNow\n")
        # Just print a preview
        for i, rec in enumerate(SEED_RECORDS, 1):
            print(f"  [{i:02d}] [{rec['short_description']}]")
            print(f"        CI      : {rec['cmdb_ci']}")
            print(f"        Summary : {rec['summary']}")
            print(f"        Risk    : {rec['risk_rating']} | Score: {rec['risk_score']} | QID: {rec['u_qid']}")
            print()
        print(f"  Total: {len(SEED_RECORDS)} records would be created.")
        return

    seeder = ServiceNowSeeder(args.instance_url, args.username, args.password)

    if not seeder.test_connection():
        sys.exit(1)

    if args.delete_demo:
        deleted = seeder.delete_demo_records()
        print(f"\n  [DONE] Deleted {deleted} demo records from ServiceNow.")
        return

    created_ids = seeder.seed_records(dry_run=False)

    print("\n" + "=" * 60)
    print(f"  [OK] Seeded {len(created_ids)} / {len(SEED_RECORDS)} records successfully.")
    print(f"  Verify in ServiceNow:")
    print(f"     Table   : {seeder.table}")
    print(f"     Filter  : Assignment group contains S-TCS-DC AND state = Open")
    print(f"     Marker  : u_demo_marker = {DEMO_MARKER}")
    print("=" * 60)

    if created_ids:
        seeder.save_created_ids(created_ids)


if __name__ == "__main__":
    main()
