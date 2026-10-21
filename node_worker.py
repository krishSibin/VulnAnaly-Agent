"""
Node Worker — Copy this single file to each target laptop.
Run with: python node_worker.py

This script:
1. Announces the laptop as a "server node" to the master agent dashboard.
2. Listens on port 9001 for remediation commands from the master.
3. Executes or simulates patch commands locally and streams back live logs.
4. Shows a terminal UI so the demo audience can watch patches applying in real-time.

Usage on each target laptop:
    python node_worker.py --node-id node_1 --master-ip 192.168.1.100
"""

import argparse
import hashlib
import html
import http.server
import json
import urllib.error
import urllib.parse
import urllib.request
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time

# Windows consoles/redirects default to cp1252, which can't print the emoji below.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

# ─────────────────────────────────────────────────────────
# NODE IDENTITY  (auto-detected but can be overridden)
# ─────────────────────────────────────────────────────────
NODE_DEFAULTS = {
    "node_1": {
        "label": "WINTEL-SERVER-01",
        "ci_names": ["pvwiihamwaapg110", "ppwischwaapg003", "ppwischwaapg004", "evwidc4lfgic225", "PPEDC1FHVG166"],
        "os": "Windows Server 2022",
        "team": "S-TCS-DC-WINTEL",
    },
    "node_2": {
        "label": "WINTEL-SERVER-02",
        "ci_names": ["pvwidc1tccxg037", "pvwidc1tccxg054", "pvwihamifcxg029", "PPEDC1FHVG167", "PPEDC2FHVG125"],
        "os": "Windows Server 2019",
        "team": "S-TCS-DC-WINTEL",
    },
    "node_3": {
        "label": "WINTEL-SERVER-03",
        "ci_names": ["pvwihamifcxg031", "pvwihamifcxg028", "pvwihamifcxg027", "PPEDC3FHVG126"],
        "os": "Windows Server 2022",
        "team": "S-TCS-DC-WINTEL",
    },
}

MASTER_PORT = 8000
WORKER_PORT = 9001

# Single-node mode keeps its identity here; multi-node mode stores it on each server.
node_info = {}


def get_local_ip():
    """Get this machine's local network IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def print_banner(node_id, label, ip):
    print("\n" + "=" * 62)
    print(f"  🛡️  TCS Vulnerability Remediation Agent — NODE WORKER")
    print("=" * 62)
    print(f"  Node ID  : {node_id}")
    print(f"  Label    : {label}")
    print(f"  Host IP  : {ip}")
    print(f"  Listener : http://{ip}:{WORKER_PORT}")
    print(f"  Platform : {platform.system()} {platform.release()}")
    print("=" * 62)
    print("  STATUS: Waiting for remediation commands from master...\n")


# ─────────────────────────────────────────────────────────
# REAL REMEDIATION (check / install)
# The node decides what it is allowed to run. The master only names a fix_id
# from this list plus the minimum safe version; any command text it sends is ignored.
# ─────────────────────────────────────────────────────────
FIX_ACTIONS = {
    "chrome": {
        "label": "Google Chrome",
        "paths": [r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
                  r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
                  r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"],
        "winget": "Google.Chrome",
    },
    "edge": {
        "label": "Microsoft Edge",
        "paths": [r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
                  r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"],
        "winget": "Microsoft.Edge",
    },
    "7zip": {
        "label": "7-Zip",
        "paths": [r"%ProgramFiles%\7-Zip\7z.exe", r"%ProgramFiles(x86)%\7-Zip\7z.exe"],
        "winget": "7zip.7zip",
    },
    "notepadpp": {
        "label": "Notepad++",
        "paths": [r"%ProgramFiles%\Notepad++\notepad++.exe", r"%ProgramFiles(x86)%\Notepad++\notepad++.exe"],
        "winget": "Notepad++.Notepad++",
    },
    "adobe_reader": {
        "label": "Adobe Acrobat Reader",
        "paths": [r"%ProgramFiles%\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
                  r"%ProgramFiles(x86)%\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"],
        "winget": "Adobe.Acrobat.Reader.64-bit",
    },
}

# Three simulated servers share one laptop; only one installer may run at a time.
INSTALL_LOCK = threading.Lock()


def file_version(path):
    """Product version of a Windows executable, e.g. '125.0.6422.60', or None."""
    if sys.platform != "win32" or not os.path.isfile(path):
        return None
    import ctypes
    from ctypes import wintypes

    ver = ctypes.WinDLL("version")
    ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    ver.GetFileVersionInfoW.restype = wintypes.BOOL
    ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
    ver.VerQueryValueW.restype = wintypes.BOOL

    size = ver.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(path, 0, size, buf):
        return None
    ptr, length = ctypes.c_void_p(), wintypes.UINT()
    if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
        return None

    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [(n, wintypes.DWORD) for n in (
            "dwSignature", "dwStrucVersion", "dwFileVersionMS", "dwFileVersionLS",
            "dwProductVersionMS", "dwProductVersionLS", "dwFileFlagsMask", "dwFileFlags",
            "dwFileOS", "dwFileType", "dwFileSubtype", "dwFileDateMS", "dwFileDateLS")]

    info = ctypes.cast(ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    ms, ls = info.dwProductVersionMS, info.dwProductVersionLS
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def version_tuple(v):
    parts = [int(x) for x in re.findall(r"\d+", v or "")][:4]
    return tuple(parts + [0] * (4 - len(parts)))


def installed(action):
    """(path, version) of the first installed copy, or (None, None)."""
    for p in action["paths"]:
        path = os.path.expandvars(p)
        v = file_version(path)
        if v:
            return path, v
    return None, None


# ─────────────────────────────────────────────────────────
# VERSION POLICY (approved_versions.json next to this file, optional)
#   "latest" : install the newest version (default)
#   "exact"  : install the required version — or the "version" IT approved —
#              from winget (pinned) or from an approved installer with a known SHA256.
#              If neither has it, install nothing and report it.
# ─────────────────────────────────────────────────────────
POLICY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "approved_versions.json")


def load_version_policy():
    if not os.path.exists(POLICY_FILE):
        return {}
    try:
        with open(POLICY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)}
    except (OSError, ValueError) as e:
        print(f"  ⚠ Could not read {POLICY_FILE}: {e}. Using 'latest' for everything.")
        return {}


VERSION_POLICY = load_version_policy()


def _run(cmd, log, timeout=900):
    """Run an allow-listed command, stream readable output to the log, return the exit code (None on error)."""
    log("$ " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except FileNotFoundError:
        log(f"{cmd[0]} is not available on this machine.")
        return None
    except subprocess.TimeoutExpired:
        log(f"{cmd[0]} did not finish within {timeout // 60} minutes.")
        return None
    for line in (proc.stdout + proc.stderr).splitlines():
        line = line.strip()
        # winget draws progress bars and spinners; keep only readable lines
        if line and re.search(r"[A-Za-z]{3}", line) and not re.fullmatch(r"[\W_\d]+", line):
            log("  " + line[:160])
    log(f"exit code: {proc.returncode}")
    return proc.returncode


WINGET_FLAGS = ["--exact", "--silent", "--accept-package-agreements",
                "--accept-source-agreements", "--disable-interactivity"]


def winget_versions(package_id):
    """Versions of a package that winget's catalogue can install."""
    try:
        out = subprocess.run(["winget", "show", "--id", package_id, "--exact", "--versions",
                              "--accept-source-agreements", "--disable-interactivity"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return [l.strip() for l in out.splitlines() if re.fullmatch(r"\d+(\.\d+)+", l.strip())]


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def install_update(fix_id, action, fixed, log):
    """
    Install according to the version policy. Returns None if something was run,
    or "version_unavailable" if the exact version can't be obtained (nothing installed).
    """
    policy = VERSION_POLICY.get(fix_id, {})
    if policy.get("policy", "latest") != "exact":
        log("Version policy: latest (install the newest version)")
        _run(["winget", "upgrade", "--id", action["winget"], *WINGET_FLAGS], log)
        return None

    target = policy.get("version") or fixed
    log(f"Version policy: exact, target version {target or 'unknown'}")
    if not target:
        log("No target version: the vendor solution has no version and none is set in approved_versions.json.")
        return "version_unavailable"

    # 1) winget, pinned to the exact version
    log(f"Looking for {target} in the winget catalogue...")
    if target in winget_versions(action["winget"]):
        _run(["winget", "install", "--id", action["winget"], "--version", target, "--force", *WINGET_FLAGS], log)
        return None
    log(f"{target} is not in the winget catalogue.")

    # 2) approved installer kept by IT, checked against its SHA256
    installer, expected = policy.get("installer"), (policy.get("sha256") or "").lower()
    if installer:
        log(f"Using approved installer {installer}")
        if not os.path.isfile(installer):
            log("Approved installer not found at that path.")
            return "version_unavailable"
        if not expected:
            log("No sha256 set for the approved installer in approved_versions.json; refusing to run it.")
            return "version_unavailable"
        actual = sha256_of(installer)
        if actual != expected:
            log(f"SHA256 mismatch: expected {expected[:16]}…, file is {actual[:16]}…. Not installing.")
            return "version_unavailable"
        log("SHA256 matches the approved fingerprint.")
        if installer.lower().endswith(".msi"):
            _run(["msiexec.exe", "/i", installer, "/qn", "/norestart"], log)
        else:
            _run([installer, *policy.get("args", [])], log)
        return None

    # 3) nowhere to get it: install nothing
    log(f"No approved installer configured for {action['label']} {target}. Nothing installed.")
    return "version_unavailable"


def run_remediation(payload, mode, log):
    """
    Check (and in install mode, fix) one finding on this machine.
    Returns a dict with status, verified, before/after/fixed versions.
    status: already_fixed | fixed | vulnerable | failed | not_installed | manual
    """
    fix_id = payload.get("fix_id") or "manual"
    fixed = payload.get("fixed_version") or ""
    action = FIX_ACTIONS.get(fix_id)
    result = {"fix_id": fix_id, "mode": mode, "fixed_version": fixed,
              "before_version": None, "after_version": None, "verified": False}

    if not action:
        log(f"No automated fix for '{fix_id}' on this node. Apply manually:")
        log(f"  {payload.get('vendor_solution') or payload.get('recommended_action') or 'see the vendor advisory'}")
        return {**result, "status": "manual"}

    log(f"Checking installed {action['label']}...")
    path, before = installed(action)
    result["before_version"] = before
    if not path:
        log(f"{action['label']} is not installed on this machine. Nothing to check or patch.")
        return {**result, "status": "not_installed"}
    log(f"Found {path}")
    log(f"Installed version : {before}")
    log(f"Fixed in version  : {fixed or 'unknown (no version in the vendor solution)'}")

    if fixed and version_tuple(before) >= version_tuple(fixed):
        log(f"RESULT: {before} is at or above {fixed}. Not vulnerable, no change needed.")
        return {**result, "status": "already_fixed", "after_version": before, "verified": True}

    if mode != "install":
        log("RESULT: still VULNERABLE. This node runs in check-only mode, so nothing was changed.")
        policy = VERSION_POLICY.get(fix_id, {})
        if policy.get("policy") == "exact":
            log(f"Install mode would install exactly {policy.get('version') or fixed} (version policy: exact)")
        else:
            log(f"Install mode would run: winget upgrade --id {action['winget']} --exact --silent")
        return {**result, "status": "vulnerable", "after_version": before}

    with INSTALL_LOCK:
        problem = install_update(fix_id, action, fixed, log)
    if problem:
        log(f"RESULT: NOT FIXED. The approved version of {action['label']} is not available, so nothing was installed.")
        return {**result, "status": problem, "after_version": before}

    after = installed(action)[1]
    result["after_version"] = after
    if fixed and after and version_tuple(after) >= version_tuple(fixed):
        log(f"RESULT: VERIFIED. {action['label']} is now {after} (needs {fixed}).")
        return {**result, "status": "fixed", "verified": True}
    log(f"RESULT: NOT FIXED. {action['label']} is {after or 'unknown'}"
        f"{f' (needs {fixed})' if fixed else ''}.")
    return {**result, "status": "failed"}



def init_server_state(server, info, mode="check"):
    server.node_info = info
    server.mode = mode               # "check" (read-only) or "install" (runs winget)
    server.execution_log = []
    server.pending_approvals = {}    # sys_id → request from master
    server.decided_approvals = []    # most recent first
    server.last_error = ""


def send_decision_to_master(req, approved, approver, comments):
    """POST the server team's decision back to the master. Returns (ok, message)."""
    url = f"http://{req['master_ip']}:{MASTER_PORT}/api/approval/callback"
    body = json.dumps({
        "sys_id": req["sys_id"], "token": req["token"], "approved": approved,
        "approver": approver, "comments": comments,
    }).encode()
    try:
        r = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(r, timeout=5):
            return True, ""
    except urllib.error.HTTPError as e:
        return False, f"Master rejected the decision (HTTP {e.code}): {e.read().decode()[:200]}"
    except Exception as e:
        return False, f"Could not reach master at {url}: {e}"


def pending_signature(server):
    """Changes whenever a request arrives or is decided; the page reloads only then."""
    return ",".join(sorted(server.pending_approvals)) + "|" + str(len(server.decided_approvals))


def _tier(req):
    r = str(req.get("risk_rating") or "").strip()[:1]
    try:
        s = int(float(req.get("risk_score") or 0))
    except (TypeError, ValueError):
        s = 0
    if r not in ("1", "2", "3", "4"):
        r = "1" if s >= 90 else "2" if s >= 70 else "3" if s >= 40 else "4" if s > 0 else "5"
    return {"1": ("crit", "Critical"), "2": ("high", "High"), "3": ("mod", "Moderate"),
            "4": ("low", "Low"), "5": ("none", "Not rated")}[r], (s if s > 0 else "—")


PAGE_CSS = """
  :root{--bg:#EDF0F3;--surface:#fff;--surface-2:#F5F7F9;--ink:#132030;--ink-2:#3A4A5C;--muted:#687787;--rule:#D6DDE4;--rule-2:#E6EBF0;
        --bar:#132030;--crit:#C2362B;--high:#C9741A;--mod:#9C8A22;--low:#5D7A93;--none:#8A97A4;--ok:#2D7A57;
        --display:"Archivo","Arial Narrow",sans-serif;--sans:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",Consolas,monospace;}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:400 14px/1.5 var(--sans)}
  :focus-visible{outline:2px solid #1F5FBF;outline-offset:2px}
  .bar{background:var(--bar);color:#C9D4DF;padding:16px 28px}
  .bar-in{max-width:780px;margin:auto;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .bar svg{width:26px;height:26px;fill:none;stroke:#fff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
  .bar h1{margin:0;font:700 20px/1 var(--display);font-stretch:80%;color:#fff}
  .bar .sub{font:400 12px var(--mono);color:#8496A8;margin-top:4px}
  .live{margin-left:auto;display:inline-flex;align-items:center;gap:6px;font-size:12px}
  .live i{width:7px;height:7px;border-radius:50%;background:#4CC38A;box-shadow:0 0 0 3px rgba(76,195,138,.18)}
  main{max-width:780px;margin:auto;padding:28px 28px 60px}
  .lede{color:var(--ink-2);margin:0 0 18px;font-size:15px}
  .req{position:relative;background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:22px 24px 22px 28px;margin-bottom:16px;box-shadow:0 1px 2px rgba(19,32,48,.06),0 2px 8px rgba(19,32,48,.04)}
  .req::before{content:"";position:absolute;left:-1px;top:-1px;bottom:-1px;width:4px;border-radius:6px 0 0 6px;background:var(--tier)}
  .t-crit{--tier:var(--crit)} .t-high{--tier:var(--high)} .t-mod{--tier:var(--mod)} .t-low{--tier:var(--low)} .t-none{--tier:var(--none)}
  .req-head{display:flex;gap:18px;align-items:flex-start}
  .score{display:flex;flex-direction:column;line-height:1;min-width:56px}
  .score-n{font:800 48px/.9 var(--display);font-stretch:62%;color:var(--tier)}
  .score-l{font:500 10.5px var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--tier);margin-top:6px}
  .ids{font:400 12px var(--mono);color:var(--muted)}
  h2{margin:4px 0 0;font:700 22px/1.15 var(--display);font-stretch:80%}
  h2.unlinked{color:var(--muted);font-style:italic}
  .host{font:500 13px var(--mono);color:var(--ink-2);margin-top:6px}
  dl.facts{display:grid;grid-template-columns:110px 1fr;gap:6px 16px;margin:18px 0 0;font-size:13.5px}
  .facts dt{color:var(--muted)} .facts dd{margin:0}
  .term{margin:14px 0 0;background:var(--bar);color:#fff;border-radius:6px;padding:12px 14px;font:400 12.5px/1.6 var(--mono);white-space:pre-wrap;word-break:break-all}
  .why{margin:14px 0 0;color:var(--ink-2)}
  .note{margin:14px 0 0;padding:10px 14px;background:var(--surface-2);border-left:3px solid var(--rule);border-radius:0 6px 6px 0}
  .note span{display:block;font:500 11px var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:2px}
  .decide{margin-top:20px;padding-top:18px;border-top:1px solid var(--rule-2)}
  .fields{display:grid;grid-template-columns:1fr 1.4fr;gap:12px}
  label{display:flex;flex-direction:column;gap:5px;font-size:13px;font-weight:500;color:var(--ink-2)}
  input{height:36px;padding:0 10px;border:1px solid var(--rule);border-radius:6px;font:inherit;font-weight:400}
  .buttons{display:flex;gap:10px;justify-content:flex-end;margin-top:14px}
  .btn{height:38px;padding:0 18px;border-radius:6px;font:600 14px var(--sans);cursor:pointer;border:1px solid}
  .approve{background:var(--ok);border-color:var(--ok);color:#fff} .approve:hover{background:#246247}
  .reject{background:#fff;border-color:#E3B9B4;color:var(--crit)} .reject:hover{background:#FBE9E7}
  .empty{background:var(--surface);border:1px dashed var(--rule);border-radius:6px;padding:40px;text-align:center;color:var(--muted)}
  .error{background:#FBE9E7;border:1px solid #E3B9B4;color:#7A2119;border-radius:6px;padding:12px 14px;margin-bottom:16px}
  h3{font:500 11px var(--mono);text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:30px 0 10px}
  table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--rule);border-radius:6px;overflow:hidden}
  td{padding:10px 14px;border-bottom:1px solid var(--rule-2);font-size:13.5px} tr:last-child td{border-bottom:0}
  .mono{font-family:var(--mono);font-size:12.5px}
  .tag{font-size:12px;font-weight:500;padding:1px 8px;border-radius:10px}
  .tag.ok{color:var(--ok);background:#E8F3EE} .tag.no{color:var(--crit);background:#FBE9E7}
  @media (max-width:640px){.bar,main{padding-left:16px;padding-right:16px} .fields{grid-template-columns:1fr} dl.facts{grid-template-columns:1fr;gap:0} .facts dd{margin-bottom:8px} .buttons .btn{flex:1} .req{padding:18px 16px 18px 20px} table{display:block;overflow-x:auto}}
"""

PAGE_JS = """
  // Reload only when a request arrives or is decided, never while someone is typing
  setInterval(async () => {
    if (document.activeElement && document.activeElement.tagName === 'INPUT') return;
    try {
      const r = await fetch('/pending');
      if ((await r.json()).signature !== SIG) location.reload();
    } catch (e) {}
  }, 2500);
"""


def render_approvals_page(server):
    """Approval page for this node's server team (same look as the master's Remediation Desk)."""
    info = server.node_info
    esc = lambda v: html.escape(str(v if v is not None else ""))
    label = esc(info.get("label"))

    cards = []
    for req in server.pending_approvals.values():
        (tcls, tlabel), score = _tier(req)
        summary = str(req.get("summary") or "").strip()
        linked = bool(summary) and not summary.startswith("...")
        title = esc(summary) if linked else "No vulnerability linked in ServiceNow"
        reboot = "Required, in the next maintenance window" if req.get("requires_reboot") else "Not needed"
        note = req.get("requester_comments")
        why = req.get("risk_assessment")
        cards.append(f"""
      <article class="req t-{tcls}">
        <header class="req-head">
          <div class="score"><span class="score-n">{esc(score)}</span><span class="score-l">{tlabel}</span></div>
          <div>
            <div class="ids">{esc(req.get('remediation_task'))} · received {esc(req.get('received_at'))}</div>
            <h2 class="{'' if linked else 'unlinked'}">{title}</h2>
            <div class="host">{esc(req.get('configuration_item'))}</div>
          </div>
        </header>
        <dl class="facts">
          <dt>Patch</dt><dd>{esc(req.get('patch_type'))}</dd>
          <dt>Software</dt><dd>{esc(req.get('target_software'))}</dd>
          <dt>Source</dt><dd>{esc(req.get('dl_source'))}</dd>
          <dt>Reboot</dt><dd>{reboot}</dd>
        </dl>
        <pre class="term">$ {esc(req.get('fix_command'))}</pre>
        {f'<p class="why">{esc(why)}</p>' if why else ''}
        {f'<p class="note"><span>Note from the agent operator</span>{esc(note)}</p>' if note else ''}
        <form method="post" action="/approval-decision" class="decide">
          <input type="hidden" name="sys_id" value="{esc(req.get('sys_id'))}">
          <div class="fields">
            <label>Your name<input name="approver" value="{label} owner" required></label>
            <label>Comment (optional)<input name="comments" placeholder="e.g. OK for tonight's window"></label>
          </div>
          <div class="buttons">
            <button name="decision" value="reject" class="btn reject">Reject</button>
            <button name="decision" value="approve" class="btn approve">Approve patch</button>
          </div>
        </form>
      </article>""")

    rows = []
    for d in server.decided_approvals[:10]:
        verdict = '<span class="tag ok">Approved</span>' if d["approved"] else '<span class="tag no">Rejected</span>'
        rows.append(f"<tr><td class='mono'>{esc(d['decided_at'])}</td><td class='mono'>{esc(d.get('configuration_item'))}</td>"
                    f"<td>{esc(d.get('summary') or '—')}</td><td>{verdict}</td><td>{esc(d.get('approver'))}</td></tr>")
    history = f"<h3>Recent decisions</h3><table>{''.join(rows)}</table>" if rows else ""

    error = (f'<div class="error"><b>Your decision was not delivered.</b> {esc(server.last_error)}</div>'
             if server.last_error else "")
    count = len(server.pending_approvals)
    lede = (f"{count} request{'s' if count != 1 else ''} waiting for your decision." if count
            else "Nothing waiting. New requests appear here on their own.")
    empty = '<div class="empty">When the Remediation Desk asks to patch one of your servers, the request shows up here.</div>'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{label} approvals</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,500..800&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>{PAGE_CSS}</style></head><body>
<header class="bar"><div class="bar-in">
  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>
  <div><h1>{label} · patch approvals</h1><div class="sub">{esc(info.get('team'))} · {esc(', '.join(info.get('ci_names', [])))}</div></div>
  <span class="live"><i></i>Listening for requests</span>
</div></header>
<main>
  {error}
  <p class="lede">{lede}</p>
  {''.join(cards) or empty}
  {history}
</main>
<script>const SIG = {json.dumps(pending_signature(server))};{PAGE_JS}</script>
</body></html>"""


class NodeServer(http.server.ThreadingHTTPServer):
    # On Windows, address reuse lets a second process bind the same port and silently
    # receive some of its requests. Fail loudly instead.
    allow_reuse_address = False

    def server_bind(self):
        try:
            super().server_bind()
        except OSError:
            print(f"\n  ❌ Port {self.server_address[1]} is already in use. Another node_worker is probably "
                  f"still running: stop it (Ctrl+C in its terminal) and start this one again.\n")
            raise SystemExit(1)


class NodeHandler(http.server.BaseHTTPRequestHandler):
    @property
    def info(self):
        return self.server.node_info

    @property
    def execution_log(self):
        return self.server.execution_log

    """Lightweight HTTP handler on port 9001 receiving commands from master."""

    def log_message(self, format, *args):
        pass  # Suppress default HTTP log noise

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "status": "online",
                "node_id": self.info.get("node_id"),
                "label": self.info.get("label"),
                "ip": self.info.get("ip"),
                "platform": f"{platform.system()} {platform.release()}",
                "mode": self.server.mode,
            })
        elif self.path == "/logs":
            self._send_json(200, {"logs": self.execution_log})
        elif self.path == "/pending":
            self._send_json(200, {"signature": pending_signature(self.server)})
        elif self.path in ("/", "/approvals"):
            self._send_html(200, render_approvals_page(self.server))
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/approval-request":
            payload = self._read_json()
            if payload is None or not payload.get("sys_id") or not payload.get("token"):
                self._send_json(400, {"error": "Invalid approval request"})
                return
            # The master's address is whoever sent this request; the decision goes back there.
            payload["master_ip"] = self.client_address[0]
            payload["received_at"] = time.strftime("%H:%M:%S")
            self.server.pending_approvals[payload["sys_id"]] = payload

            port = self.info.get("port")
            print(f"\n{'─' * 62}")
            print(f"  🔔 [{self.info.get('label')}] APPROVAL REQUESTED")
            print(f"  Server   : {payload.get('configuration_item')}")
            print(f"  Issue    : {payload.get('summary')}")
            print(f"  Patch    : {payload.get('patch_type')}")
            print(f"  ➜ Approve or reject at http://127.0.0.1:{port}/")
            print(f"{'─' * 62}\n")
            self._send_json(200, {"status": "received", "node": self.info.get("label")})

        elif self.path == "/approval-decision":
            length = int(self.headers.get("Content-Length", 0))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            sys_id = form.get("sys_id", [""])[0]
            req = self.server.pending_approvals.get(sys_id)
            if req:
                approved = form.get("decision", [""])[0] == "approve"
                approver = form.get("approver", [""])[0].strip()
                comments = form.get("comments", [""])[0].strip()
                ok, msg = send_decision_to_master(req, approved, approver, comments)
                if ok:
                    self.server.pending_approvals.pop(sys_id, None)
                    self.server.decided_approvals.insert(0, {
                        **req, "approved": approved, "approver": approver, "comments": comments,
                        "decided_at": time.strftime("%H:%M:%S"),
                    })
                    verdict = "APPROVED" if approved else "REJECTED"
                    print(f"  {'✅' if approved else '⛔'} [{self.info.get('label')}] {verdict} "
                          f"{req.get('configuration_item')} by {approver or 'server owner'} — master notified.")
                    self.server.last_error = ""
                else:
                    self.server.last_error = msg
            # Post/redirect/get so a page refresh doesn't resubmit the form
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

        elif self.path == "/remediate":
            payload = self._read_json()
            if payload is None:
                self._send_json(400, {"error": "Invalid JSON"})
                return

            label = self.info.get("label")
            logs = []
            self.execution_log.clear()     # /logs streams this run while it's in progress

            def log(line):
                logs.append(line)
                self.execution_log.append(line)
                print(f"  [{label}] {line}")

            print(f"\n{'─' * 62}")
            print(f"  📥 [{label}] REMEDIATION ({self.server.mode.upper()} MODE)")
            print(f"  Finding : {payload.get('summary', '')}")
            print(f"  Server  : {payload.get('configuration_item', '')}")
            print(f"{'─' * 62}")

            result = run_remediation(payload, self.server.mode, log)
            print(f"{'─' * 62}\n")
            self._send_json(200, {**result, "node": label, "logs": logs})
        else:
            self._send_json(404, {"error": "Not found"})

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    def _send_html(self, code, page):
        body = page.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def register_with_master(master_ip, info):
    """Announce this node to the master agent so it shows up in the dashboard."""
    import urllib.request
    url = f"http://{master_ip}:{MASTER_PORT}/api/nodes/register"
    payload = json.dumps({
        "node_id": info["node_id"],
        "label": info["label"],
        "ci_names": info["ci_names"],
        "ip": info["ip"],
        "port": info["port"],
        "team": info["team"],
    }).encode()

    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())
                print(f"  ✅ Registered with master at {master_ip}:{MASTER_PORT}")
                print(f"     Response: {result.get('message', 'OK')}")
                return True
        except Exception as e:
            print(f"  ⚠ Registration attempt {attempt}/5 failed: {e}")
            time.sleep(3)

    print(f"  ❌ Could not reach master at {master_ip}:{MASTER_PORT}.")
    print(f"     Running in standalone mode — master can still discover via health check.")
    return False


def start_node(node_id, port, ip, master_ip=None, mode="check"):
    """Start one node worker on a background thread. Returns the server."""
    d = NODE_DEFAULTS[node_id]
    server = NodeServer((ip, port), NodeHandler)
    init_server_state(server, {"node_id": node_id, "label": d["label"], "ci_names": d["ci_names"],
                               "ip": ip, "port": port, "team": d["team"]}, mode)
    threading.Thread(target=server.serve_forever, daemon=True, name=node_id).start()
    if master_ip:
        threading.Thread(target=register_with_master, args=(master_ip, server.node_info), daemon=True).start()
    return server


def run_all(master_ip="127.0.0.1", base_port=WORKER_PORT, mode="check"):
    """Imitate every node on this laptop: one thread + port each (9001, 9002, ...)."""
    for i, node_id in enumerate(NODE_DEFAULTS):
        start_node(node_id, base_port + i, "127.0.0.1", master_ip, mode)
        print(f"  🟢 {NODE_DEFAULTS[node_id]['label']} listening on 127.0.0.1:{base_port + i}"
              f"  —  approvals page: http://127.0.0.1:{base_port + i}/")
    print(f"  Mode: {'INSTALL (runs winget upgrades on this machine)' if mode == 'install' else 'CHECK ONLY (reads versions, changes nothing)'}")
    exact = [k for k, v in VERSION_POLICY.items() if v.get("policy") == "exact"]
    print(f"  Version policy: exact for {', '.join(exact)}; latest for everything else" if exact
          else "  Version policy: latest for everything (no approved_versions.json)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  🔴 Node workers stopped.")


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Agent Node Worker")
    parser.add_argument("--node-id", default="node_1",
                        choices=["node_1", "node_2", "node_3"],
                        help="Which server node this laptop represents")
    parser.add_argument("--master-ip", default=None,
                        help="IP address of the master agent laptop (optional)")
    parser.add_argument("--port", type=int, default=WORKER_PORT,
                        help="Port to listen on (default: 9001)")
    parser.add_argument("--all", action="store_true",
                        help="Run all nodes on this one machine, each on its own thread/port")
    parser.add_argument("--install", action="store_true",
                        help="Really install updates with winget. Default is check-only (read versions, change nothing)")
    args = parser.parse_args()
    mode = "install" if args.install else "check"

    if args.all:
        run_all(args.master_ip or "127.0.0.1", args.port, mode)
        return

    # Build node identity
    defaults = NODE_DEFAULTS.get(args.node_id, NODE_DEFAULTS["node_1"])
    local_ip = get_local_ip()

    node_info.update({
        "node_id": args.node_id,
        "label": defaults["label"],
        "ci_names": defaults["ci_names"],
        "ip": local_ip,
        "port": args.port,
        "team": defaults["team"],
    })

    print_banner(args.node_id, defaults["label"], local_ip)

    # Try to register with master
    if args.master_ip:
        t = threading.Thread(target=register_with_master, args=(args.master_ip, node_info), daemon=True)
        t.start()
    else:
        print("  ℹ  No --master-ip specified. Waiting to be discovered...")
        print(f"     Run on master: Nodes page will show this node at {local_ip}:{args.port}\n")

    # Start HTTP server
    server = NodeServer(("0.0.0.0", args.port), NodeHandler)
    init_server_state(server, node_info, mode)
    print(f"  🟢 Node worker listening on port {args.port} ({mode} mode) ...\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  🔴 Node worker stopped.")


if __name__ == "__main__":
    main()
