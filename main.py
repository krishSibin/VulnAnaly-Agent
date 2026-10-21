import itertools
import json
import logging
import os
import secrets
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from servicenow_client import ServiceNowClient
from remediation_engine import RemediationFixEngine
from agent import VulnerabilityAgent

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("VulnAgent")

app = FastAPI(title="Vulnerability Analysis & Automated Remediation Agent POC")

@app.middleware("http")
async def revalidate_ui(request, call_next):
    """Make browsers re-check the dashboard files, so UI updates show up without a hard refresh."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBAL STATE
# ─────────────────────────────────────────────────────────────────────────────
state: Dict[str, Any] = {
    "vulnerabilities":  [],
    "approvals":        {},   # sys_id → {status, team, comments}
    "execution_history": [],
    # node_id → {node_id, label, ci_names, ip, port, team, status, last_seen}
    "nodes": {},
    "activity": [],          # live feed of everything the agent does
    "running": set(),        # sys_ids being remediated right now
    # Autopilot: ask for approval automatically, patch as soon as a team approves
    "automation": {
        "enabled":   os.getenv("AUTOPILOT", "1") != "0",
        "min_score": int(os.getenv("AUTOPILOT_MIN_SCORE", "70")),
    },
    # Background ServiceNow sync status (shown on the dashboard)
    "sync": {"interval_minutes": None, "last_at": None, "next_at": None, "last_trigger": None,
             "new": 0, "updated": 0, "closed": 0, "error": None, "running": False},
}

snow_client = ServiceNowClient()
agent       = VulnerabilityAgent()

# ─────────────────────────────────────────────────────────────────────────────
#  LOAD SERVER REGISTRY  (server_registry.json)
#  Nodes listed there are "known" even before they register/come online
# ─────────────────────────────────────────────────────────────────────────────
_registry_path = os.path.join(os.path.dirname(__file__), "server_registry.json")
if os.path.exists(_registry_path):
    with open(_registry_path) as f:
        _reg = json.load(f)
    for n in _reg.get("nodes", []):
        state["nodes"][n["node_id"]] = {**n, "status": "offline", "last_seen": None}
    logger.info(f"Loaded {len(state['nodes'])} nodes from server_registry.json")


# ─────────────────────────────────────────────────────────────────────────────
#  PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────
class ConfigPayload(BaseModel):
    instance_url:    Optional[str] = ""
    username:        Optional[str] = ""
    password:        Optional[str] = ""
    gemini_api_key:  Optional[str] = ""
    tcs_gateway_key: Optional[str] = ""

class ApprovalPayload(BaseModel):
    sys_id:   str
    approved: bool
    comments: Optional[str] = ""

class ApprovalRequestPayload(BaseModel):
    sys_id:   str
    comments: Optional[str] = ""

class ApprovalCallbackPayload(BaseModel):
    sys_id:   str
    token:    str
    approved: bool
    approver: Optional[str] = ""
    comments: Optional[str] = ""

class FixPayload(BaseModel):
    sys_id:   str
    simulate: Optional[bool] = True

class NodeRegisterPayload(BaseModel):
    node_id:   str
    label:     str
    ci_names:  List[str]
    ip:        str
    port:      int
    team:      Optional[str] = "S-TCS-DC-WINTEL"

class NodeIPUpdatePayload(BaseModel):
    node_id: str
    ip:      str
    port:    Optional[int] = 9001


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS — NODE COMMUNICATION
# ─────────────────────────────────────────────────────────────────────────────
def _find_node_for_ci(ci_name: str) -> Optional[Dict]:
    """Return the registered node whose ci_names list includes this CI."""
    for node in state["nodes"].values():
        if ci_name in node.get("ci_names", []):
            return node
    return None


def _ping_node(node: Dict) -> bool:
    """Quick health-check ping to a node worker."""
    url = f"http://{node['ip']}:{node['port']}/health"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
            node["mode"] = data.get("mode", "check")
            return data.get("status") == "online"
    except Exception:
        return False


def _post_to_node(node: Dict, path: str, payload: Dict, timeout: int = 5) -> Dict:
    req = urllib.request.Request(
        f"http://{node['ip']}:{node['port']}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _public_approval(sys_id: str) -> Dict:
    """Approval details safe to send to the browser (no token)."""
    a = state["approvals"].get(sys_id, {})
    return {k: v for k, v in a.items() if k != "token"}


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/config")
def get_config():
    return {
        "servicenow_configured": snow_client.is_configured(),
        "instance_url":          snow_client.instance_url,
        "gemini_configured":     bool(agent.gemini_key),
        "tcs_gateway_configured": bool(agent.tcs_key),
        "llm_mode":              agent.mode_label,
        "llm_key_rejected":      agent.key_rejected,
    }


@app.post("/api/config")
def update_config(payload: ConfigPayload):
    global snow_client, agent

    if payload.instance_url and payload.username and payload.password:
        snow_client = ServiceNowClient(
            instance_url=payload.instance_url,
            username=payload.username,
            password=payload.password,
        )

    if payload.tcs_gateway_key or payload.gemini_api_key:
        agent = VulnerabilityAgent(
            gemini_api_key  = payload.gemini_api_key  or None,
            tcs_gateway_key = payload.tcs_gateway_key or None,
        )

    return {"status": "ok", "llm_mode": agent.mode_label}


# ─────────────────────────────────────────────────────────────────────────────
#  NODE MANAGEMENT ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/nodes")
def get_nodes():
    """Returns all known nodes with current online/offline status."""
    nodes_with_status = []
    for node in state["nodes"].values():
        is_online = _ping_node(node)
        node["status"] = "online" if is_online else "offline"
        if is_online:
            node["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        nodes_with_status.append(node)
    return {"nodes": nodes_with_status}


@app.post("/api/nodes/register")
def register_node(payload: NodeRegisterPayload):
    """Called by node_worker.py on each target laptop when it starts up."""
    node_id = payload.node_id
    state["nodes"][node_id] = {
        "node_id":   node_id,
        "label":     payload.label,
        "ci_names":  payload.ci_names,
        "ip":        payload.ip,
        "port":      payload.port,
        "team":      payload.team,
        "status":    "online",
        "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    logger.info(f"Node registered: {payload.label} at {payload.ip}:{payload.port}")
    return {"status": "ok", "message": f"Node {payload.label} registered successfully."}


@app.post("/api/nodes/update-ip")
def update_node_ip(payload: NodeIPUpdatePayload):
    """Lets you quickly update a node's IP from the Settings tab without restarting."""
    if payload.node_id not in state["nodes"]:
        raise HTTPException(status_code=404, detail="Node not found in registry")
    state["nodes"][payload.node_id]["ip"]   = payload.ip
    state["nodes"][payload.node_id]["port"] = payload.port
    return {"status": "ok", "message": f"Node {payload.node_id} IP updated to {payload.ip}:{payload.port}"}


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
SYNC_INTERVAL_MINUTES = float(os.getenv("SYNC_INTERVAL_MINUTES", "10"))
_sync_lock = threading.Lock()

# Fields owned by the agent, not by ServiceNow: kept when a finding is re-synced
_AGENT_FIELDS = ("llm_analysis", "llm_mode_used", "approval_status", "approval_info",
                 "responsible_team", "added_at", "new", "fix_strategy")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _tag_node(item: Dict) -> None:
    node = _find_node_for_ci(item.get("configuration_item", ""))
    item["target_node_id"]    = node["node_id"] if node else None
    item["target_node_label"] = node["label"]   if node else "Master (Local)"


def sync_from_servicenow(trigger: str = "manual") -> Dict[str, int]:
    """
    Merge the open findings in ServiceNow into the agent's list.
      new      — analysed (AI or rules) and added
      existing — ServiceNow fields refreshed; analysis, approvals and history kept
      gone     — no longer open in ServiceNow: marked "Closed in ServiceNow"
    Only one sync runs at a time; a second caller waits for the first to finish.
    """
    with _sync_lock:
        state["sync"]["running"] = True
        try:
            raw_vulns = snow_client.fetch_vulnerabilities()
        except Exception as e:
            state["sync"].update({"running": False, "error": str(e), "last_at": _now_iso(),
                                  "last_trigger": trigger})
            raise

        first_sync = not state["vulnerabilities"]
        current = {v["sys_id"]: v for v in state["vulnerabilities"]}
        seen, added, updated = set(), 0, 0

        for raw in raw_vulns:
            sys_id = raw.get("sys_id")
            if not sys_id:
                continue
            seen.add(sys_id)
            item = current.get(sys_id)
            if item:
                # Update in place so requests holding this dict see the new values
                keep = {k: item[k] for k in _AGENT_FIELDS if k in item}
                locally_closed = str(item.get("state", "")).startswith("Closed")
                item.update(raw)
                item.update(keep)
                if locally_closed:
                    item["state"] = "Closed (Remediated)"
                item["fix_strategy"] = RemediationFixEngine.identify_remediation_strategy(item)
                updated += 1
            else:
                item = agent.analyze_vulnerability_with_llm(raw)
                item["added_at"] = _now_iso()
                item["new"] = not first_sync
                current[sys_id] = item
                added += 1
            if sys_id not in state["approvals"]:
                state["approvals"][sys_id] = {
                    "status":   "Pending",
                    "team":     item.get("responsible_team", "S-TCS-DC-WINTEL"),
                    "comments": "",
                }
            item["approval_status"] = state["approvals"][sys_id]["status"]
            item["approval_info"]   = _public_approval(sys_id)
            _tag_node(item)

        closed = 0
        for sys_id, item in current.items():
            if sys_id not in seen and not str(item.get("state", "")).startswith("Closed"):
                item["state"] = "Closed in ServiceNow"
                closed += 1

        state["vulnerabilities"] = agent.prioritize_vulnerabilities(list(current.values()))
        stats = {"new": added, "updated": updated, "closed": closed}
        state["sync"].update({**stats, "running": False, "error": None, "last_at": _now_iso(),
                              "last_trigger": trigger})
        logger.info(f"ServiceNow sync ({trigger}): {added} new, {updated} updated, {closed} closed elsewhere")
        if added or closed or trigger == "manual":
            activity(f"Synced with ServiceNow: {added} new, {updated} updated"
                     f"{f', {closed} closed in ServiceNow' if closed else ''}", source="servicenow")
        return stats


def _sync_loop() -> None:
    """Sync once at startup, then every SYNC_INTERVAL_MINUTES."""
    interval = SYNC_INTERVAL_MINUTES * 60
    state["sync"]["interval_minutes"] = SYNC_INTERVAL_MINUTES
    while True:
        if snow_client.is_configured():
            try:
                sync_from_servicenow(trigger="auto")
                _autopilot()
            except Exception as e:
                logger.warning(f"Scheduled ServiceNow sync failed: {e}")
                activity(f"Scheduled ServiceNow sync failed: {e}", level="error", source="servicenow")
        state["sync"]["next_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + interval))
        time.sleep(interval)


@app.on_event("startup")
def _start_background_sync() -> None:
    if SYNC_INTERVAL_MINUTES > 0:
        threading.Thread(target=_sync_loop, daemon=True, name="servicenow-sync").start()
        logger.info(f"Background ServiceNow sync every {SYNC_INTERVAL_MINUTES:g} minutes")


@app.post("/api/fetch-vulnerabilities")
def fetch_and_analyze():
    """Sync now: merge ServiceNow's open findings into the list (same as the scheduled sync)."""
    try:
        stats = sync_from_servicenow(trigger="manual")
        threading.Thread(target=_autopilot, daemon=True).start()
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error fetching from ServiceNow: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error fetching from ServiceNow: {e}")
        raise HTTPException(status_code=500, detail=f"ServiceNow connection failure: {e}")

    return {
        "status":   "success",
        "total":    len(state["vulnerabilities"]),
        "source":   "ServiceNow Table API",
        "llm_mode": agent.mode_label,
        "sync":     {**state["sync"], **stats},
        "data":     state["vulnerabilities"],
    }


@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    for v in state["vulnerabilities"]:
        sys_id = v.get("sys_id")
        if sys_id in state["approvals"]:
            v["approval_status"] = state["approvals"][sys_id]["status"]
            v["approval_info"]   = _public_approval(sys_id)
    return {"total": len(state["vulnerabilities"]), "sync": state["sync"], "automation": state["automation"],
            "running": sorted(state["running"]), "data": state["vulnerabilities"]}


# ─────────────────────────────────────────────────────────────────────────────
#  APPROVAL
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
#  ACTIVITY FEED — every step the agent takes, shown live on the dashboard
# ─────────────────────────────────────────────────────────────────────────────
_activity_lock = threading.Lock()
_activity_seq = itertools.count(1)


def activity(text: str, item: Optional[Dict] = None, level: str = "info", source: str = "agent") -> None:
    """level: info | ok | warn | error   source: agent | node | ai | servicenow | team"""
    entry = {
        "id":     next(_activity_seq),
        "at":     _now_iso(),
        "level":  level,
        "source": source,
        "text":   text,
        "sys_id": item.get("sys_id") if item else None,
        "number": item.get("remediation_task") if item else None,
        "server": item.get("configuration_item") if item else None,
    }
    with _activity_lock:
        state["activity"].append(entry)
        del state["activity"][:-1000]
    if source != "node":
        logger.info(f"[{source}] {entry['number'] or ''} {text}")


# ─────────────────────────────────────────────────────────────────────────────
#  APPROVAL (shared by the autopilot and the dashboard)
# ─────────────────────────────────────────────────────────────────────────────
def _send_for_approval(item: Dict, comments: str, requested_by: str) -> Dict:
    """Send an approval request to the node that owns this CI. Raises RuntimeError on failure."""
    sys_id = item["sys_id"]
    if state["approvals"].get(sys_id, {}).get("status") == "Approved":
        raise RuntimeError("Already approved")
    ci   = item.get("configuration_item", "")
    node = _find_node_for_ci(ci)
    if not node:
        raise RuntimeError(f"No server node owns {ci}. Add it to a node's ci_names in server_registry.json.")

    fix   = item.get("fix_strategy") or RemediationFixEngine.identify_remediation_strategy(item)
    llm   = item.get("llm_analysis") or {}
    token = secrets.token_urlsafe(16)
    try:
        _post_to_node(node, "/approval-request", {
            "sys_id":             sys_id,
            "token":              token,
            "configuration_item": ci,
            "summary":            item.get("summary", ""),
            "remediation_task":   item.get("remediation_task", ""),
            "risk_rating":        item.get("risk_rating", ""),
            "risk_score":         item.get("risk_score", 0),
            "patch_type":         fix.get("patch_type"),
            "target_software":    fix.get("target_software"),
            "fix_command":        fix.get("fix_command"),
            "dl_source":          fix.get("dl_source"),
            "requires_reboot":    fix.get("requires_reboot", False),
            "risk_assessment":    llm.get("risk_assessment", ""),
            "request_message":    llm.get("approval_request_message", ""),
            "requester_comments": comments,
        })
    except Exception as e:
        raise RuntimeError(f"{node['label']} is not reachable ({e}). Start node_worker.py and try again.")

    state["approvals"][sys_id] = {
        "status":       "Awaiting Approval",
        "team":         item.get("responsible_team", "S-TCS-DC-WINTEL"),
        "comments":     comments,
        "requested_by": requested_by,
        "node_id":      node["node_id"],
        "node_label":   node["label"],
        "node_url":     f"http://{node['ip']}:{node['port']}/",
        "requested_at": _now_iso(),
        "token":        token,
    }
    item["approval_status"] = "Awaiting Approval"
    item["approval_info"]   = _public_approval(sys_id)
    activity(f"Asked {node['label']}'s team to approve {fix.get('patch_type')} "
             f"({'by the agent' if requested_by == 'agent' else 'from the dashboard'})", item)
    return {"node": node["label"], "node_url": state["approvals"][sys_id]["node_url"]}


@app.post("/api/approval/request")
def request_server_approval(payload: ApprovalRequestPayload):
    """Dashboard: send an approval request to the node that owns this CI."""
    item = next((v for v in state["vulnerabilities"] if v.get("sys_id") == payload.sys_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    try:
        sent = _send_for_approval(item, payload.comments or "", requested_by="operator")
    except RuntimeError as e:
        raise HTTPException(status_code=502 if "not reachable" in str(e) else 400, detail=str(e))
    return {"status": "success", "approval_status": "Awaiting Approval", **sent}


@app.post("/api/approval/callback")
def approval_callback(payload: ApprovalCallbackPayload):
    """Called by a node worker when its server team approves or rejects a request."""
    approval = state["approvals"].get(payload.sys_id)
    if not approval or approval.get("status") != "Awaiting Approval":
        raise HTTPException(status_code=409, detail="No approval is pending for this item")
    if not secrets.compare_digest(payload.token, approval.get("token", "")):
        raise HTTPException(status_code=403, detail="Invalid approval token")

    new_status = "Approved" if payload.approved else "Rejected"
    approval.pop("token")
    approval.update({
        "status":     new_status,
        "approver":   payload.approver or f"{approval['node_label']} owner",
        "comments":   payload.comments or approval.get("comments", ""),
        "decided_at": _now_iso(),
    })
    item = next((v for v in state["vulnerabilities"] if v.get("sys_id") == payload.sys_id), None)
    if item:
        item["approval_status"] = new_status
        item["approval_info"]   = _public_approval(payload.sys_id)
        activity(f"{approval['node_label']}: {new_status.lower()} by {approval['approver']}"
                 f"{f' — “{payload.comments}”' if payload.comments else ''}",
                 item, level="ok" if payload.approved else "warn", source="team")
        snow_client.add_work_note(payload.sys_id, f"Patch {new_status.lower()} by {approval['approver']} "
                                                  f"({approval['node_label']}). {payload.comments or ''}".strip())
        # Autopilot: an approval is the go-ahead to patch
        if payload.approved and state["automation"]["enabled"]:
            threading.Thread(target=_remediate, args=(item, "agent"), daemon=True).start()
    return {"status": "ok", "approval_status": new_status}


# ─────────────────────────────────────────────────────────────────────────────
#  REMEDIATION — runs in the background; node output streams into the feed
# ─────────────────────────────────────────────────────────────────────────────
_node_locks: Dict[str, threading.Lock] = {}


def _get_node_logs(node: Dict) -> List[str]:
    try:
        with urllib.request.urlopen(f"http://{node['ip']}:{node['port']}/logs", timeout=3) as resp:
            return json.loads(resp.read()).get("logs", [])
    except Exception:
        return []


def _remediate(item: Dict, started_by: str) -> None:
    """Check/fix one approved finding on its node, verify, and update ServiceNow."""
    sys_id = item["sys_id"]
    if sys_id in state["running"]:
        return
    approval = state["approvals"].get(sys_id, {})
    node = _find_node_for_ci(item.get("configuration_item", ""))
    if approval.get("status") != "Approved" or not node:
        return
    state["running"].add(sys_id)
    entry = None
    try:
        fix = RemediationFixEngine.identify_remediation_strategy(item)
        item["fix_strategy"] = fix
        entry = {
            "sys_id":            sys_id,
            "server":            item.get("configuration_item"),
            "summary":           item.get("summary"),
            "patch_applied":     fix.get("patch_type"),
            "target_software":   fix.get("target_software"),
            "dl_source":         fix.get("dl_source"),
            "executed_on_node":  node["label"],
            "executed_at":       _now_iso(),
            "started_by":        started_by,
            "approved_by":       approval.get("approver", ""),
            "mode":              node.get("mode", "check"),
            "result":            "running",
            "outcome":           "Running…",
            "verified":          False,
            "logs":              [],
            "servicenow_synced": False,
            "servicenow_closed": False,
        }
        state["execution_history"].insert(0, entry)

        lock = _node_locks.setdefault(node["node_id"], threading.Lock())
        if lock.locked():
            activity(f"Queued: {node['label']} is busy with another patch", item)
        with lock:
            activity(f"Starting remediation on {node['label']} ({fix.get('target_software')}, "
                     f"fixed in {fix.get('fixed_version') or 'n/a'})", item)
            box: Dict[str, Any] = {}

            def call():
                try:
                    box["result"] = _post_to_node(node, "/remediate", {
                        "sys_id":             sys_id,
                        "configuration_item": item.get("configuration_item"),
                        "summary":            item.get("summary", ""),
                        "fix_id":             fix.get("fix_id"),
                        "fixed_version":      fix.get("fixed_version"),
                        "vendor_solution":    item.get("vendor_solution", ""),
                        "recommended_action": fix.get("recommended_action"),
                    }, timeout=960)
                except Exception as e:
                    box["error"] = e

            worker = threading.Thread(target=call, daemon=True)
            worker.start()
            seen = 0
            while worker.is_alive():
                worker.join(1.5)
                lines = _get_node_logs(node)
                for line in lines[seen:]:
                    entry["logs"].append(line)
                    activity(line, item, source="node")
                seen = max(seen, len(lines))

        if "error" in box:
            entry.update({"result": "failed", "outcome": f"{node['label']} not reachable: nothing changed."})
            activity(f"{node['label']} is not reachable. Nothing changed; will retry on the next sync.",
                     item, level="error")
            return

        result = box["result"]
        for line in result.get("logs", [])[seen:]:
            activity(line, item, source="node")
        verified = bool(result.get("verified"))
        status   = result.get("status", "failed")
        before, after, fixed = result.get("before_version"), result.get("after_version"), result.get("fixed_version")
        outcome = {
            "already_fixed": f"Already at a safe version ({before}, fixed in {fixed}). No change needed.",
            "fixed":         f"Upgraded {before} -> {after} (fixed in {fixed}). Verified.",
            "vulnerable":    f"Still vulnerable: {before} installed, fixed in {fixed}. Node is check-only, nothing changed.",
            "failed":        f"Fix attempted but not verified (installed: {after or before or 'unknown'}, needs {fixed or 'unknown'}).",
            "not_installed": "Software not found on the node. Nothing to patch.",
            "manual":        "No automated fix for this type. Needs a manual patch.",
            "version_unavailable": "The approved version is not available (not in winget, no approved installer). Nothing installed.",
        }.get(status, status)
        entry.update({
            "mode": result.get("mode", entry["mode"]), "result": status, "outcome": outcome, "verified": verified,
            "before_version": before, "after_version": after, "fixed_version": fixed,
            "logs": result.get("logs", entry["logs"]),
        })
        note = f"Remediation Agent on {node['label']} ({entry['mode']} mode): {outcome}"

        if verified:
            activity(outcome, item, level="ok")
            ok = snow_client.update_remediation_status(sys_id=sys_id, new_state="Closed", work_notes=note)
            item["state"] = "Closed (Remediated)"
            item["percent_remediated"] = "100.00"
            entry.update({"servicenow_synced": ok, "servicenow_closed": ok})
            activity(f"Closed {item.get('remediation_task')} in ServiceNow" if ok
                     else "Could not close the item in ServiceNow", item,
                     level="ok" if ok else "warn", source="servicenow")
        else:
            activity(outcome, item, level="warn")
            review = agent.review_remediation(item, result)
            entry["ai_review"] = review
            activity(f"{review['summary']} Next step: {review['next_step']}", item, level="warn", source="ai")
            ok = snow_client.add_work_note(sys_id, f"{note} Item left open.\n"
                                                   f"Agent review: {review['summary']} Next step: {review['next_step']}")
            entry["servicenow_synced"] = ok
            activity("Left open in ServiceNow with the agent's review as a work note" if ok
                     else "Could not add the work note in ServiceNow", item, source="servicenow")
    except Exception as e:
        logger.exception("Remediation failed")
        if entry:
            entry.update({"result": "failed", "outcome": f"Agent error: {e}"})
        activity(f"Agent error during remediation: {e}", item, level="error")
    finally:
        state["running"].discard(sys_id)


@app.post("/api/remediate")
def apply_fix(payload: FixPayload):
    """Dashboard: start remediation of an approved finding now (the autopilot does this on approval)."""
    item = next((v for v in state["vulnerabilities"] if v.get("sys_id") == payload.sys_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    approval = state["approvals"].get(payload.sys_id, {})
    if approval.get("status") != "Approved":
        raise HTTPException(status_code=400, detail=f"Fix blocked — approval status is "
                                                    f"'{approval.get('status', 'Pending')}'. Team approval required first.")
    node = _find_node_for_ci(item.get("configuration_item", ""))
    if not node:
        raise HTTPException(status_code=400, detail=f"No server node owns {item.get('configuration_item')}.")
    if payload.sys_id in state["running"]:
        raise HTTPException(status_code=409, detail="Remediation is already running for this item")
    threading.Thread(target=_remediate, args=(item, "operator"), daemon=True).start()
    return {"status": "started", "executed_on_node": node["label"]}


# ─────────────────────────────────────────────────────────────────────────────
#  AUTOPILOT — after each sync, ask for approval on findings that need it
# ─────────────────────────────────────────────────────────────────────────────
def _autopilot() -> None:
    auto = state["automation"]
    if not auto["enabled"]:
        return
    asked, offline = 0, set()
    for item in list(state["vulnerabilities"]):
        sys_id = item["sys_id"]
        if str(item.get("state", "")).startswith("Closed") or sys_id in state["running"]:
            continue
        status = state["approvals"].get(sys_id, {}).get("status", "Pending")
        node_id = item.get("target_node_id")

        # Approved earlier (e.g. while the autopilot was paused) and never run: patch it now
        if status == "Approved" and not any(h["sys_id"] == sys_id for h in state["execution_history"]):
            threading.Thread(target=_remediate, args=(item, "agent"), daemon=True).start()
            continue

        if status != "Pending" or not node_id or node_id in offline:
            continue
        if int(item.get("risk_score") or 0) < auto["min_score"]:
            continue
        note = (item.get("llm_analysis") or {}).get("approval_request_message") or \
               "Requesting approval for automated patch execution."
        try:
            _send_for_approval(item, note, requested_by="agent")
            asked += 1
        except RuntimeError as e:
            offline.add(node_id)
            activity(f"Could not ask for approval: {e}", item, level="warn")
    if asked:
        activity(f"Autopilot sent {asked} approval request{'s' if asked != 1 else ''} to server teams")


class AutomationPayload(BaseModel):
    enabled:   Optional[bool] = None
    min_score: Optional[int] = None


@app.get("/api/automation")
def get_automation():
    return state["automation"]


@app.post("/api/automation")
def set_automation(payload: AutomationPayload):
    auto = state["automation"]
    if payload.min_score is not None:
        auto["min_score"] = max(0, min(100, payload.min_score))
    if payload.enabled is not None and payload.enabled != auto["enabled"]:
        auto["enabled"] = payload.enabled
        activity("Autopilot resumed" if payload.enabled else "Autopilot paused: nothing will be sent or patched "
                 "automatically", level="ok" if payload.enabled else "warn")
        if payload.enabled:
            threading.Thread(target=_autopilot, daemon=True).start()
    return auto


@app.get("/api/activity")
def get_activity(after: int = 0, limit: int = 300):
    with _activity_lock:
        items = [a for a in state["activity"] if a["id"] > after]
    return {"activity": items[-limit:]}


@app.get("/api/history")
def get_history():
    return {"history": state["execution_history"]}


# ─────────────────────────────────────────────────────────────────────────────
#  STATIC UI
# ─────────────────────────────────────────────────────────────────────────────
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if not os.path.exists(index_file):
        return {"message": "Vulnerability Analysis Agent API is running."}
    page = open(index_file, encoding="utf-8").read()
    # Version the CSS/JS URLs by file time so browsers never reuse a stale cached copy
    for asset in ("css/style.css", "js/app.js"):
        path = os.path.join(static_dir, *asset.split("/"))
        if os.path.exists(path):
            page = page.replace(f"/static/{asset}\"", f"/static/{asset}?v={int(os.path.getmtime(path))}\"")
    return HTMLResponse(page, headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    import uvicorn
    # Bind to 0.0.0.0 so other laptops on the same network can reach the UI.
    # Auto-reload restarts the process on every file change and wipes the in-memory
    # findings and approvals, so it's off unless AGENT_RELOAD=1.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=os.getenv("AGENT_RELOAD") == "1")
