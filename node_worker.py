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
import http.server
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time

# ─────────────────────────────────────────────────────────
# NODE IDENTITY  (auto-detected but can be overridden)
# ─────────────────────────────────────────────────────────
NODE_DEFAULTS = {
    "node_1": {
        "label": "WINTEL-SERVER-01",
        "ci_names": ["pvwiihamwaapg110", "ppwischwaapg003"],
        "os": "Windows Server 2022",
        "team": "S-TCS-DC-WINTEL",
    },
    "node_2": {
        "label": "WINTEL-SERVER-02",
        "ci_names": ["pvwidc1tccxg037", "pvwidc1tccxg054"],
        "os": "Windows Server 2019",
        "team": "S-TCS-DC-WINTEL",
    },
    "node_3": {
        "label": "WINTEL-SERVER-03",
        "ci_names": ["pvwihamifcxg031", "pvwihamifcxg028"],
        "os": "Windows Server 2022",
        "team": "S-TCS-DC-WINTEL",
    },
}

MASTER_PORT = 8000
WORKER_PORT = 9001

# In-memory execution log (shared between HTTP handler and main loop)
execution_log = []
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


def simulate_patch(patch_type, target_software, fix_command, dl_source, requires_reboot, configuration_item):
    """Run a simulated (safe) patch and yield log lines."""
    logs = [
        f"[AGENT→NODE] Remediation command received from master.",
        f"[NODE] Target Host       : {configuration_item}",
        f"[NODE] Patch Type        : {patch_type}",
        f"[NODE] Target Software   : {target_software}",
        f"[NODE] Download Source   : {dl_source}",
        f"[NODE] Running command...",
        f"[NODE] $ {fix_command}",
        f"[NODE] Downloading patch binary... ████████████ 100%",
        f"[NODE] Verifying vendor binary signature... OK",
        f"[NODE] Applying patch silently... ████████████ 100%",
        f"[NODE] Post-patch validation: Vulnerability signature RESOLVED.",
        f"[NODE] Exit Code: 0 (SUCCESS)",
    ]
    if requires_reboot:
        logs.append(f"[NODE] ⚠ Server reboot scheduled for next maintenance window.")
    logs.append(f"[NODE] ✅ Remediation complete. Notifying master agent...")
    return logs


class NodeHandler(http.server.BaseHTTPRequestHandler):
    """Lightweight HTTP handler on port 9001 receiving commands from master."""

    def log_message(self, format, *args):
        pass  # Suppress default HTTP log noise

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "status": "online",
                "node_id": node_info.get("node_id"),
                "label": node_info.get("label"),
                "ip": node_info.get("ip"),
                "platform": f"{platform.system()} {platform.release()}"
            })
        elif self.path == "/logs":
            self._send_json(200, {"logs": execution_log})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/remediate":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body)
            except Exception:
                self._send_json(400, {"error": "Invalid JSON"})
                return

            patch_type = payload.get("patch_type", "Generic Patch")
            target_software = payload.get("target_software", "Unknown Software")
            fix_command = payload.get("fix_command", "echo Simulated patch")
            dl_source = payload.get("dl_source", "Vendor Portal")
            requires_reboot = payload.get("requires_reboot", False)
            ci = payload.get("configuration_item", node_info.get("label", "server"))
            summary = payload.get("summary", "Vulnerability")

            print(f"\n{'─' * 62}")
            print(f"  📥 REMEDIATION COMMAND RECEIVED FROM MASTER AGENT")
            print(f"{'─' * 62}")
            print(f"  Vulnerability : {summary}")
            print(f"  Patch Type    : {patch_type}")
            print(f"  Target        : {target_software}")
            print(f"{'─' * 62}")

            logs = simulate_patch(patch_type, target_software, fix_command, dl_source, requires_reboot, ci)

            execution_log.clear()
            for log_line in logs:
                execution_log.append(log_line)
                print(f"  {log_line}")
                time.sleep(0.3)  # Dramatic effect for demo

            print(f"\n  ✅ PATCH APPLIED SUCCESSFULLY. Node notified master.")
            print(f"{'─' * 62}\n")

            self._send_json(200, {
                "status": "success",
                "node": node_info.get("label"),
                "logs": logs
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def register_with_master(master_ip):
    """Announce this node to the master agent so it shows up in the dashboard."""
    import urllib.request
    url = f"http://{master_ip}:{MASTER_PORT}/api/nodes/register"
    payload = json.dumps({
        "node_id": node_info["node_id"],
        "label": node_info["label"],
        "ci_names": node_info["ci_names"],
        "ip": node_info["ip"],
        "port": WORKER_PORT,
        "team": node_info["team"],
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


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Agent Node Worker")
    parser.add_argument("--node-id", default="node_1",
                        choices=["node_1", "node_2", "node_3"],
                        help="Which server node this laptop represents")
    parser.add_argument("--master-ip", default=None,
                        help="IP address of the master agent laptop (optional)")
    parser.add_argument("--port", type=int, default=WORKER_PORT,
                        help="Port to listen on (default: 9001)")
    args = parser.parse_args()

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
        t = threading.Thread(target=register_with_master, args=(args.master_ip,), daemon=True)
        t.start()
    else:
        print("  ℹ  No --master-ip specified. Waiting to be discovered...")
        print(f"     Run on master: Nodes page will show this node at {local_ip}:{args.port}\n")

    # Start HTTP server
    server = http.server.HTTPServer(("0.0.0.0", args.port), NodeHandler)
    print(f"  🟢 Node worker listening on port {args.port} ...\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  🔴 Node worker stopped.")


if __name__ == "__main__":
    main()
