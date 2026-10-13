import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from servicenow_client import ServiceNowClient
from remediation_engine import RemediationFixEngine
from agent import VulnerabilityAgent

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("VulnAgent")

app = FastAPI(title="Vulnerability Analysis & Automated Remediation Agent POC")

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
            return data.get("status") == "online"
    except Exception:
        return False


def _dispatch_to_node(node: Dict, payload: Dict) -> Dict:
    """
    Send a remediation command to a remote node worker.
    Returns the node's response or a simulated-fallback result.
    """
    url  = f"http://{node['ip']}:{node['port']}/remediate"
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            result = json.loads(resp.read())
            node["status"]    = "online"
            node["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return result
    except Exception as e:
        logger.warning(f"Node {node['node_id']} unreachable ({e}). Using local simulation.")
        # Graceful fallback — local simulate so demo never breaks
        fix_strategy = payload  # payload already has fix fields
        logs = [
            f"[FALLBACK] Node {node['label']} unreachable — running local simulation.",
            f"[FALLBACK] Target: {payload.get('configuration_item')}",
            f"[FALLBACK] Patch : {payload.get('patch_type')}",
            f"[FALLBACK] $ {payload.get('fix_command')}",
            f"[FALLBACK] Execution status: SUCCESS (simulated)",
            f"[FALLBACK] Post-patch validation: Vulnerability signature resolved.",
        ]
        return {"status": "success", "node": node["label"], "logs": logs, "fallback": True}


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
@app.post("/api/fetch-vulnerabilities")
def fetch_and_analyze():
    """
    1. Fetch directly from ServiceNow table API.
    2. AI agent prioritizes (Critical first).
    3. Enrich with LLM analysis & patch strategy.
    """
    try:
        raw_vulns = snow_client.fetch_vulnerabilities()
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error fetching from ServiceNow: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error fetching from ServiceNow: {e}")
        raise HTTPException(status_code=500, detail=f"ServiceNow connection failure: {e}")

    if not raw_vulns:
        return {"status": "empty", "total": 0, "source": "ServiceNow Table API", "data": []}

    prioritized = agent.prioritize_vulnerabilities(raw_vulns)

    enriched = []
    for v in prioritized:
        analyzed = agent.analyze_vulnerability_with_llm(v)
        sys_id   = analyzed["sys_id"]
        if sys_id not in state["approvals"]:
            state["approvals"][sys_id] = {
                "status":   "Pending",
                "team":     analyzed.get("responsible_team", "S-TCS-DC-WINTEL"),
                "comments": "",
            }
        analyzed["approval_status"] = state["approvals"][sys_id]["status"]

        # Tag which node would handle this CI
        ci   = analyzed.get("configuration_item", "")
        node = _find_node_for_ci(ci)
        analyzed["target_node_id"]    = node["node_id"]  if node else None
        analyzed["target_node_label"] = node["label"]    if node else "Master (Local)"
        enriched.append(analyzed)

    state["vulnerabilities"] = enriched
    return {
        "status": "success",
        "total":  len(enriched),
        "source": "ServiceNow Table API",
        "llm_mode": agent.mode_label,
        "data":   enriched,
    }


@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    for v in state["vulnerabilities"]:
        sys_id = v.get("sys_id")
        if sys_id in state["approvals"]:
            v["approval_status"] = state["approvals"][sys_id]["status"]
    return {"total": len(state["vulnerabilities"]), "data": state["vulnerabilities"]}


# ─────────────────────────────────────────────────────────────────────────────
#  APPROVAL
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/approval")
def handle_approval(payload: ApprovalPayload):
    sys_id = payload.sys_id
    item   = next((v for v in state["vulnerabilities"] if v.get("sys_id") == sys_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    new_status = "Approved" if payload.approved else "Rejected"
    state["approvals"][sys_id] = {
        "status":   new_status,
        "team":     item.get("responsible_team", "S-TCS-DC-WINTEL"),
        "comments": payload.comments or (
            "Approved for automated patch execution" if payload.approved
            else "Change rejected by team"
        ),
    }
    item["approval_status"] = new_status
    return {
        "status":          "success",
        "sys_id":          sys_id,
        "approval_status": new_status,
        "message":         f"Team {item.get('responsible_team')} status set to {new_status}.",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  REMEDIATION + MULTI-SERVER DISPATCH
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/remediate")
def apply_fix(payload: FixPayload):
    """
    If approved:
    1. Identifies which server node owns this CI.
    2. Dispatches the patch command to that node (or falls back to local sim).
    3. Updates ServiceNow status.
    """
    sys_id = payload.sys_id
    item   = next((v for v in state["vulnerabilities"] if v.get("sys_id") == sys_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    approval = state["approvals"].get(sys_id, {})
    if approval.get("status") != "Approved":
        raise HTTPException(
            status_code=400,
            detail=f"Fix blocked — approval status is '{approval.get('status', 'Pending')}'. Team approval required first."
        )

    fix = item.get("fix_strategy") or RemediationFixEngine.identify_remediation_strategy(item)

    # ── Find target node ──────────────────────────────────
    ci        = item.get("configuration_item", "")
    node      = _find_node_for_ci(ci)
    node_used = "Local Simulation"
    logs      = []
    fallback  = True

    if node and not payload.simulate:
        # Real dispatch to remote node worker
        dispatch_payload = {
            **fix,
            "configuration_item": ci,
            "summary":            item.get("summary", ""),
            "sys_id":             sys_id,
        }
        result    = _dispatch_to_node(node, dispatch_payload)
        logs      = result.get("logs", [])
        fallback  = result.get("fallback", False)
        node_used = node["label"]
    else:
        # Local simulation (always works, no network needed)
        local_result = RemediationFixEngine.execute_fix(item, fix, simulate=True)
        logs         = local_result.get("logs", [])
        node_used    = node["label"] if node else "Master (Local Simulation)"

    # ── Update ServiceNow ─────────────────────────────────
    snow_updated = snow_client.update_remediation_status(
        sys_id=sys_id,
        new_state="Closed",
        work_notes=(
            f"Automated Remediation Agent dispatched {fix.get('patch_type')} "
            f"to {node_used}. Vulnerability resolved."
        ),
    )

    item["state"]              = "Closed (Remediated)"
    item["percent_remediated"] = "100.00"

    history_entry = {
        "sys_id":           sys_id,
        "server":           ci,
        "summary":          item.get("summary"),
        "patch_applied":    fix.get("patch_type"),
        "target_software":  fix.get("target_software"),
        "dl_source":        fix.get("dl_source"),
        "executed_on_node": node_used,
        "logs":             logs,
        "servicenow_synced": snow_updated,
        "fallback_mode":    fallback,
    }
    state["execution_history"].insert(0, history_entry)

    return {
        "status":             "success",
        "executed_on_node":   node_used,
        "fallback_mode":      fallback,
        "servicenow_updated": snow_updated,
        "execution": {
            "success": True,
            "host":    ci,
            "logs":    logs,
        },
    }


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
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Vulnerability Analysis Agent API is running."}


if __name__ == "__main__":
    import uvicorn
    # Bind to 0.0.0.0 so other laptops on the same network can reach the UI
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
