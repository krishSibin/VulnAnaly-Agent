import os
import json
import logging
from typing import List, Dict, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

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
            return self._normalize_snow_records(raw_results, is_incident=(target_table == "incident"))
        else:
            err_msg = f"ServiceNow API error ({response.status_code}): {response.text}"
            logger.error(err_msg)
            raise RuntimeError(err_msg)

    def _normalize_snow_records(self, records: List[Dict[str, Any]], is_incident: bool = False) -> List[Dict[str, Any]]:
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
                # sn_vul_vulnerable_item field mapping
                desc = r.get("description", "") or ""
                
                # Parse QID from description field
                qid = "QID-GENERIC"
                if "QID: " in desc:
                    try:
                        qid = desc.split("QID: ")[1].split("\n")[0].strip()
                    except Exception:
                        pass

                # cmdb_ci can be a display_value dict or a plain string
                ci_val = r.get("cmdb_ci", {})
                ci_name = ci_val.get("display_value", "") if isinstance(ci_val, dict) else str(ci_val or "Unknown-Host")
                if not ci_name:
                    ci_name = str(ci_val) if ci_val else "Unknown-Host"

                # assignment_group
                ag_val = r.get("assignment_group", {})
                ag_name = ag_val.get("display_value", "") if isinstance(ag_val, dict) else str(ag_val or "S-TCS-DC-WINTEL")
                if not ag_name:
                    ag_name = "S-TCS-DC-WINTEL"

                # risk_rating: 1=Critical,2=High,3=Moderate,4=Low (stored as int choice)
                rr_raw = r.get("risk_rating", "2")
                rr_val = rr_raw.get("value", rr_raw) if isinstance(rr_raw, dict) else str(rr_raw)
                rr_map = {"1": "1 - Critical", "2": "2 - High", "3": "3 - Moderate", "4": "4 - Low"}
                risk_rating_label = rr_map.get(str(rr_val), f"{rr_val} - High")

                # state: 1=Open,3=In Progress,6=Resolved,7=Closed
                st_raw = r.get("state", "1")
                st_val = st_raw.get("value", st_raw) if isinstance(st_raw, dict) else str(st_raw)
                st_map = {"1": "Open", "2": "In Progress", "3": "In Progress", "6": "Resolved", "7": "Closed"}
                state_label = st_map.get(str(st_val), "Open")

                # risk_score
                rs_raw = r.get("risk_score", r.get("source_risk_score", "70"))
                try:
                    rs_val = int(float(str(rs_raw)))
                except Exception:
                    rs_val = 70

                # business_criticality: 1=Critical,2=High,3=Non-critical,4=Low
                bc_raw = r.get("business_criticality", "3")
                bc_val = bc_raw.get("value", bc_raw) if isinstance(bc_raw, dict) else str(bc_raw)
                bc_map = {"1": "1 - Critical", "2": "2 - High", "3": "3 - Non-critical", "4": "4 - Low"}
                biz_impact = bc_map.get(str(bc_val), "3 - Non-critical")

                # VIT number (VIT0010001 etc.)
                vit_number = r.get("number", "")

                normalized.append({
                    "sys_id": r.get("sys_id", ""),
                    "short_description": r.get("short_description", "Vulnerability Finding"),
                    "configuration_item": ci_name,
                    "remediation_task": vit_number,
                    "vulnerable_item": vit_number,
                    "description": desc,
                    "summary": r.get("short_description", ""),
                    "assignment_group": ag_name,
                    "business_impact": biz_impact,
                    "risk_rating": risk_rating_label,
                    "risk_score": rs_val,
                    "qid": qid,
                    "state": state_label,
                    "percent_remediated": "0.00",
                    "source_severity": 4 if rs_val >= 90 else (3 if rs_val >= 70 else 2),
                    "operating_environment": "Production",
                    "operational_status": "Operational"
                })
        return normalized

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
