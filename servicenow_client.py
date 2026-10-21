import html
import os
import json
import logging
import re
from typing import List, Dict, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Vulnerable item fields, plus the linked vulnerability (Qualys QID) dot-walked in
VIT_FIELDS = ",".join([
    "sys_id", "number", "short_description", "description", "state", "source",
    "cmdb_ci", "assignment_group", "business_criticality", "risk_score", "risk_rating",
    "first_found_dt_tm", "last_found_dt_tm",
    "vulnerability.id", "vulnerability.name", "vulnerability.summary", "vulnerability.threat",
    "vulnerability.solution", "vulnerability.v3_base_score", "vulnerability.v3_base_severity",
    "vulnerability.ref_sn_vul_third_party_entry.cve_id",
])


def _text(value: str) -> str:
    """HTML field (threat, solution, proof) to plain text."""
    return html.unescape(re.sub(r"<[^>]+>", " ", value or "")).strip()

class ServiceNowClient:
    """
    Connects to ServiceNow Table API or falls back to local data if credentials are not configured.
    Target Table: sn_vul_m2m_vul_group_item (Remediation Task Items)
    """

    def __init__(self, instance_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
        self.instance_url = (instance_url or os.getenv("SERVICENOW_INSTANCE_URL", "")).rstrip("/")
        self.username = username or os.getenv("SERVICENOW_USERNAME", "")
        self.password = password or os.getenv("SERVICENOW_PASSWORD", "")
        self.table_name = "sn_vul_vulnerable_item"

    def is_configured(self) -> bool:
        return bool(self.instance_url and self.username and self.password)

    def fetch_vulnerabilities(self, assignment_group: str = "S-TCS-DC-WINTEL", query_filter: str = "") -> List[Dict[str, Any]]:
        """
        Fetches vulnerability items directly from ServiceNow REST Table API.
        Attempts sn_vul_m2m_vul_group_item first; if not present, queries incident.
        """
        if not self.is_configured():
            raise ValueError(
                "ServiceNow credentials are not configured! Please provide SERVICENOW_INSTANCE_URL, "
                "SERVICENOW_USERNAME, and SERVICENOW_PASSWORD in your .env file or via the Settings tab."
            )

        # Check preferred table
        target_table = self.table_name
        test_resp = requests.get(
            f"{self.instance_url}/api/now/table/{target_table}?sysparm_limit=1",
            auth=(self.username, self.password),
            timeout=10
        )
        if test_resp.status_code == 400:
            logger.info(f"Table {target_table} not available, querying 'incident' table...")
            target_table = "incident"
            self.table_name = "incident"

        api_url = f"{self.instance_url}/api/now/table/{target_table}"
        
        if target_table == "incident":
            sysparm_query = "category=security^ORshort_descriptionLIKEQualys^stateNOT IN6,7,8"
        else:
            sysparm_query = f"assignment_groupLIKE{assignment_group}^state=1"

        if query_filter:
            sysparm_query += f"^{query_filter}"

        params = {
            "sysparm_query": sysparm_query,
            "sysparm_limit": 50,
            "sysparm_display_value": "true"
        }
        if target_table != "incident":
            params["sysparm_fields"] = VIT_FIELDS
            params["sysparm_exclude_reference_link"] = "true"

        logger.info(f"Connecting directly to live ServiceNow API: {api_url}")
        try:
            response = requests.get(
                api_url,
                auth=(self.username, self.password),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                params=params,
                timeout=15
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to ServiceNow instance: {e}")
            raise RuntimeError(f"Could not connect to ServiceNow at {self.instance_url}: {e}")

        if response.status_code == 200:
            raw_results = response.json().get("result", [])
            logger.info(f"Successfully retrieved {len(raw_results)} records from ServiceNow {target_table}.")
            if target_table == "incident":
                return self._normalize_snow_records(raw_results, is_incident=True)
            proofs = self._fetch_detections([r.get("sys_id") for r in raw_results if r.get("sys_id")])
            return self._normalize_snow_records(raw_results, proofs=proofs)
        else:
            err_msg = f"ServiceNow API error ({response.status_code}): {response.text}"
            logger.error(err_msg)
            raise RuntimeError(err_msg)

    def _fetch_detections(self, vit_sys_ids: List[str]) -> Dict[str, Dict[str, str]]:
        """Scanner evidence per vulnerable item: proof (path + version) and solution summary."""
        if not vit_sys_ids:
            return {}
        try:
            resp = requests.get(
                f"{self.instance_url}/api/now/table/sn_vul_detection",
                auth=(self.username, self.password),
                headers={"Accept": "application/json"},
                params={
                    "sysparm_query": "vulnerable_itemIN" + ",".join(vit_sys_ids),
                    "sysparm_fields": "vulnerable_item,proof,solution_summary",
                    "sysparm_limit": 500,
                },
                timeout=15,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not read detections, continuing without proof: {e}")
            return {}
        out = {}
        for d in resp.json().get("result", []):
            vi = d.get("vulnerable_item")
            vi = vi.get("value") if isinstance(vi, dict) else vi
            out.setdefault(vi, {"proof": _text(d.get("proof")), "solution_summary": d.get("solution_summary") or ""})
        return out

    def _normalize_snow_records(self, records: List[Dict[str, Any]], is_incident: bool = False,
                                proofs: Optional[Dict[str, Dict[str, str]]] = None) -> List[Dict[str, Any]]:
        proofs = proofs or {}
        normalized = []
        for r in records:
            if is_incident:
                # Extract structured metadata from incident description if present
                desc = r.get("description", "") or ""
                summary = r.get("short_description", "Vulnerability Finding")
                if "Summary: " in desc:
                    try:
                        summary = desc.split("Summary: ")[1].split("\n")[0]
                    except Exception:
                        pass

                qid = "QID-382694"
                if "QID: " in desc:
                    try:
                        qid = desc.split("QID: ")[1].split("\n")[0]
                    except Exception:
                        pass

                task = r.get("number", "VUL0010165")
                if "Task: " in desc:
                    try:
                        task = desc.split("Task: ")[1].split("\n")[0]
                    except Exception:
                        pass

                item_code = "VIT1463963"
                if "Item: " in desc:
                    try:
                        item_code = desc.split("Item: ")[1].split("\n")[0]
                    except Exception:
                        pass

                score = 95
                if "Risk Score: " in desc:
                    try:
                        score = int(desc.split("Risk Score: ")[1].split()[0])
                    except Exception:
                        pass
                elif r.get("urgency") == "1":
                    score = 95

                ci_val = r.get("cmdb_ci", {})
                ci_name = ci_val.get("display_value", ci_val) if isinstance(ci_val, dict) else (ci_val or "ppwischwaapg003")
                if not ci_name and "Server CI: " in desc:
                    try:
                        ci_name = desc.split("Server CI: ")[1].split("\n")[0]
                    except Exception:
                        pass

                group_val = r.get("assignment_group", {})
                group_name = group_val.get("display_value", group_val) if isinstance(group_val, dict) else (group_val or "S-TCS-DC-WINTEL")

                normalized.append({
                    "sys_id": r.get("sys_id", ""),
                    "short_description": r.get("short_description", "Cyber Prioritization"),
                    "configuration_item": ci_name or "ppwischwaapg003",
                    "remediation_task": task,
                    "vulnerable_item": item_code,
                    "description": desc,
                    "summary": summary,
                    "assignment_group": group_name or "S-TCS-DC-WINTEL",
                    "business_impact": "3 - Non-critical",
                    "risk_rating": "1 - Critical" if score >= 80 else "2 - High",
                    "risk_score": score,
                    "qid": qid,
                    "state": "Open" if r.get("state") in ["1", "2", 1, 2, "New", "In Progress"] else "Closed",
                    "percent_remediated": "0.00",
                    "source_severity": 4 if score >= 80 else 3,
                    "operating_environment": "Production",
                    "operational_status": "Operational"
                })
            else:
                # sn_vul_vulnerable_item, as the Qualys integration fills it
                vul = lambda f: (r.get(f"vulnerability.{f}") or "").strip()
                try:
                    risk_score = int(float(r.get("risk_score") or 0))
                except ValueError:
                    risk_score = 0
                try:
                    cvss = float(vul("v3_base_score"))
                except ValueError:
                    cvss = None
                evidence = proofs.get(r.get("sys_id"), {})
                number = r.get("number", "")

                normalized.append({
                    "sys_id": r.get("sys_id", ""),
                    "short_description": r.get("short_description") or "",
                    "configuration_item": r.get("cmdb_ci") or "Unknown-Host",
                    "remediation_task": number,
                    "vulnerable_item": number,
                    # The scanner's proof (program path + version) is what the fix engine matches on
                    "description": evidence.get("proof") or r.get("description") or "",
                    "summary": vul("name") or r.get("short_description") or "",
                    "assignment_group": r.get("assignment_group") or "S-TCS-DC-WINTEL",
                    "business_impact": r.get("business_criticality") or "3 - Non-critical",
                    "risk_rating": r.get("risk_rating") or "",
                    "risk_score": risk_score,
                    "qid": vul("id"),
                    "cve": r.get("vulnerability.ref_sn_vul_third_party_entry.cve_id") or "",
                    "cvss_v3": cvss,
                    "cvss_severity": vul("v3_base_severity"),
                    "vulnerability_summary": vul("summary"),
                    "threat": _text(vul("threat")),
                    "vendor_solution": evidence.get("solution_summary") or _text(vul("solution")),
                    "scanner": r.get("source") or "",
                    "first_found": r.get("first_found_dt_tm") or "",
                    "last_found": r.get("last_found_dt_tm") or "",
                    "state": r.get("state") or "Open",
                    "percent_remediated": "0.00",
                    "source_severity": 4 if risk_score >= 90 else (3 if risk_score >= 70 else 2),
                    "operating_environment": "Production",
                    "operational_status": "Operational",
                })
        return normalized

    def add_work_note(self, sys_id: str, work_notes: str) -> bool:
        """Add a work note to the item without changing its state."""
        if not self.is_configured():
            return False
        try:
            resp = requests.patch(
                f"{self.instance_url}/api/now/table/{self.table_name}/{sys_id}",
                auth=(self.username, self.password),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json={"work_notes": work_notes},
                timeout=10,
            )
            return resp.status_code in (200, 204)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error adding work note to ServiceNow record {sys_id}: {e}")
            return False

    def update_remediation_status(self, sys_id: str, new_state: str = "Closed", work_notes: str = "") -> bool:
        """
        Updates state in ServiceNow after successful remediation approval and fix.
        """
        if self.is_configured():
            try:
                api_url = f"{self.instance_url}/api/now/table/{self.table_name}/{sys_id}"
                payload = {"state": new_state, "work_notes": work_notes}
                resp = requests.patch(
                    api_url,
                    auth=(self.username, self.password),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    json=payload,
                    timeout=10
                )
                return resp.status_code in [200, 204]
            except Exception as e:
                logger.error(f"Error updating ServiceNow record {sys_id}: {e}")
        return True
