"""
Azure Container Apps Sandboxes - Deploy a remote MCP server (Excalidraw)

Adapted from:
https://github.com/Azure-Samples/azure-container-apps-sandboxes/blob/main/python/samples/09-mcp-hosting/excalidraw-anonymous/python/run.py

Creates a sandbox on the ``copilot`` disk, clones and builds the
``excalidraw-mcp`` server inside it, starts it on port 80, exposes the port
anonymously (open to the internet), and verifies the public URL with a real
MCP ``initialize`` handshake over HTTPS.

Prerequisites:
  - `az login` completed
  - The resource group and sandbox group already exist (run 01-getting-started.py first)
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from azure.identity import AzureCliCredential
from azure.containerapps.sandbox import (
    SandboxGroupClient,
    SandboxGroupManagementClient,
    endpoint_for_region,
)

# ── Load configuration from .env ─────────────────────────────────────────────
load_dotenv()

resource_group_name = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
sandbox_group_name = os.getenv("SANDBOX_GROUP_NAME", "lab-01-getting-started")
location = os.getenv("LOCATION", "westus3")
mcp_disk = os.getenv("ACA_MCP_DISK", "copilot")
lab_name = Path(__file__).stem
lab_labels = {"lab": lab_name, "scenario": "mcp-hosting", "pattern": "excalidraw-anonymous"}

# Make unicode prints work on Windows cp1252 terminals.
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")

# ── Excalidraw MCP server constants ──────────────────────────────────────────
REPO_URL = "https://github.com/excalidraw/excalidraw-mcp.git"
APP_DIR = "/home/user/mcp-app"
MCP_PORT = 80
INIT_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "aca-samples-readiness-probe", "version": "1.0"},
    },
}


# ── Helpers ──────────────────────────────────────────────────────────────────
def _parse_mcp_response(body: str) -> dict[str, Any]:
    """MCP streamable-HTTP servers may reply as plain JSON or SSE-framed JSON."""
    body = body.strip()
    if body.startswith("{"):
        return json.loads(body)
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    raise ValueError(f"unrecognized MCP response shape: {body[:200]!r}")


def _poll_mcp_in_sandbox(sandbox, *, timeout_s: int = 60) -> None:
    """curl POST /mcp from inside the sandbox until we get a valid initialize result."""
    deadline = time.monotonic() + timeout_s
    payload = json.dumps(INIT_REQUEST).replace("'", "'\\''")
    cmd = (
        f"curl -fsS -X POST http://localhost:{MCP_PORT}/mcp "
        f"-H 'Content-Type: application/json' "
        f"-H 'Accept: application/json, text/event-stream' "
        f"-d '{payload}' 2>&1"
    )
    last = ""
    while time.monotonic() < deadline:
        r = sandbox.exec(cmd)
        last = (r.stdout or "").strip()
        if r.exit_code == 0 and last:
            try:
                resp = _parse_mcp_response(last)
                if resp.get("result", {}).get("protocolVersion"):
                    return
            except (ValueError, json.JSONDecodeError):
                pass
        time.sleep(2)
    log = sandbox.exec("tail -50 /tmp/excalidraw.log 2>/dev/null || true")
    raise RuntimeError(
        f"excalidraw-mcp did not become ready after {timeout_s}s.\n"
        f"last response: {last[:300]!r}\n"
        f"server log:\n{(log.stdout or '').strip()}"
    )


def _mcp_initialize_public(url: str, *, timeout_s: int = 90) -> dict[str, Any]:
    """POST /mcp initialize from the host until we get a valid response."""
    body = json.dumps(INIT_REQUEST).encode()
    deadline = time.monotonic() + timeout_s
    last_err = ""
    while time.monotonic() < deadline:
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    return _parse_mcp_response(resp.read().decode("utf-8", "replace"))
                last_err = f"http {resp.status}"
        except urllib.error.HTTPError as e:
            last_err = f"http {e.code}: {e.read()[:200]!r}"
        except urllib.error.URLError as e:
            last_err = f"urlerror {e.reason}"
        except (ValueError, json.JSONDecodeError) as e:
            last_err = f"parse error: {e}"
        time.sleep(3)
    raise RuntimeError(f"public MCP URL not ready after {timeout_s}s (last: {last_err})")


# ── Get current subscription info from Azure CLI (run `az login` first) ──────
try:
    proc = subprocess.run(
        "az account show -o json",
        capture_output=True, text=True, check=True, shell=True,
    )
    subscription = json.loads(proc.stdout)
    subscription_id = subscription["id"]
except subprocess.CalledProcessError as e:
    sys.exit(f"❌ Azure CLI not installed or not signed in. Run `az login` first.\n{e.stderr}")

cli_credential = AzureCliCredential()
sandboxgroup_mgmt_client = SandboxGroupManagementClient(
    cli_credential,
    subscription_id=subscription_id,
    resource_group=resource_group_name,
)

print(f'🧪 Lab:                   {lab_name}')
print(f'👤 User:                  {subscription["user"]["name"]}')
print(f'🏛️ Tenant Id:             {subscription["tenantId"]}')
print(f'🔑 Subscription:          {subscription["name"]} ({subscription_id})')
print(f'🌍 Target Azure Region:   {location}')
print(f'📁 Target Resource Group: {resource_group_name}')
print(f'📦 Target Sandbox Group:  {sandbox_group_name}')
print(f'💿 Disk image:            {mcp_disk}')


# ── Step 1: Verify sandbox group exists ──────────────────────────────────────
print("\n### Step 1: Verify sandbox group exists")

try:
    sandboxgroup = sandboxgroup_mgmt_client.get_group(sandbox_group_name)
    print(f'♻️ Using sandbox group: {sandboxgroup.name} ({sandboxgroup.location})')
except Exception as ex:
    sys.exit(
        f"❌ Sandbox group '{sandbox_group_name}' not found in resource group "
        f"'{resource_group_name}'. Run 01-getting-started.py first.\n{ex}"
    )

client = SandboxGroupClient(
    endpoint_for_region(sandboxgroup.location),
    cli_credential,
    subscription_id=subscription_id,
    resource_group=resource_group_name,
    sandbox_group=sandbox_group_name,
)


# ── Step 2: Create the sandbox ───────────────────────────────────────────────
print("\n### Step 2: Create the sandbox")

run_id = uuid.uuid4().hex[:8]
labels = {**lab_labels, "run": run_id}

sandbox = None
port_added = False
exit_code = 0

try:
    print(f"==> Creating sandbox (disk={mcp_disk}, run={run_id})...")
    sandbox = client.begin_create_sandbox(
        disk=mcp_disk, cpu="2000m", memory="4096Mi", labels=labels,
    ).result()
    print(f"  📦 sandbox: {sandbox.sandbox_id}")

    print("==> Waiting for exec readiness...")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if sandbox.exec("true").exit_code == 0:
            break
        time.sleep(2)
    else:
        raise RuntimeError("sandbox exec never came up")
    print("  ✅ exec ready")


    # ── Step 3: Clone, install, build excalidraw-mcp ─────────────────────────
    print("\n### Step 3: Clone, install, build excalidraw-mcp")

    print("==> Cloning excalidraw-mcp...")
    sandbox.exec("npm config set strict-ssl false")
    r = sandbox.exec(f"git clone --depth=1 {REPO_URL} {APP_DIR} 2>&1 | tail -3")
    if r.exit_code != 0:
        raise RuntimeError(f"git clone failed: {r.stdout}\n{r.stderr}")
    print("  ✅ cloned")

    print("==> Installing dependencies (this can take ~60s)...")
    r = sandbox.exec(
        f"cd {APP_DIR} && npm install --ignore-optional --no-audit --no-fund 2>&1 | tail -3"
    )
    if r.exit_code != 0:
        raise RuntimeError(f"npm install failed: {r.stdout}\n{r.stderr}")
    print("  ✅ installed")

    print("==> Building...")
    r = sandbox.exec(f"cd {APP_DIR} && npm run build 2>&1 | tail -3")
    if r.exit_code != 0:
        raise RuntimeError(f"npm run build failed: {r.stdout}\n{r.stderr}")
    print("  ✅ built")


    # ── Step 4: Start the MCP server ─────────────────────────────────────────
    print("\n### Step 4: Start the MCP server")

    print(f"==> Starting MCP server on :{MCP_PORT}...")
    sandbox.exec(
        f"cd {APP_DIR} && PORT={MCP_PORT} nohup node dist/index.js "
        f"> /tmp/excalidraw.log 2>&1 & echo $! > /tmp/excalidraw.pid"
    )

    print("==> Probing in-sandbox MCP initialize handshake...")
    _poll_mcp_in_sandbox(sandbox)
    print("  ✅ in-sandbox /mcp is alive")


    # ── Step 5: Expose port anonymously ──────────────────────────────────────
    print("\n### Step 5: Expose port anonymously")

    print(f"==> add_port({MCP_PORT}, anonymous=True)...")
    port = sandbox.add_port(MCP_PORT, anonymous=True)
    port_added = True
    public_url = getattr(port, "url", None)
    if not public_url:
        raise RuntimeError("add_port did not return a URL")
    mcp_url = public_url.rstrip("/") + "/mcp"
    print(f"  🌐 public URL: {mcp_url}")


    # ── Step 6: Verify the public MCP endpoint ───────────────────────────────
    print("\n### Step 6: Verify the public MCP endpoint")

    print("==> Verifying public MCP URL (host-side initialize)...")
    result = _mcp_initialize_public(mcp_url)
    info = result.get("result", {})
    proto = info.get("protocolVersion", "?")
    server = info.get("serverInfo", {})
    print(f"  ✅ protocolVersion={proto}  server={server.get('name', '?')}/{server.get('version', '?')}")


    # ── Step 7: Print connection instructions ────────────────────────────────
    print()
    print("=" * 72)
    print("EXCALIDRAW MCP DEPLOYED")
    print("=" * 72)
    print()
    print(f"MCP URL: {mcp_url}")
    print()
    print("Try it from THIS Copilot CLI session — ask me:")
    print(f'  "Register the MCP server at {mcp_url} for this session,')
    print('   list its tools, then draw a hello-world rectangle."')
    print()
    print("Try it from VS Code (.vscode/mcp.json):")
    print(json.dumps(
        {"servers": {"excalidraw": {"type": "http", "url": mcp_url}}},
        indent=2,
    ))
    print()
    print("Try it from Claude Desktop / ChatGPT:")
    print(f"  Settings -> Connectors -> Add custom -> {mcp_url}")
    print("=" * 72)
    print()

    try:
        input("Press Enter to delete the sandbox when you're done... ")
    except (EOFError, KeyboardInterrupt):
        print()

except Exception as ex:
    print(f"\n❌ Error: {ex}")
    exit_code = 1

finally:
    # ── Step 8: Clean up ─────────────────────────────────────────────────────
    print("\n### Step 8: Clean up")

    if sandbox is not None and port_added:
        try:
            print(f"==> remove_port({MCP_PORT})")
            sandbox.remove_port(MCP_PORT)
        except Exception as e:
            print(f"  ⚠️ remove_port failed: {e}")

    if sandbox is not None:
        try:
            print(f"==> Deleting sandbox {sandbox.sandbox_id}...")
            client.delete_sandbox(sandbox.sandbox_id)
            print("  🗑️ deleted")
        except Exception as e:
            print(f"  ⚠️ delete failed: {e}")

    try:
        client.close()
    except Exception:
        pass
    try:
        cli_credential.close()
    except Exception:
        pass

    print("\n✅ Lab complete!" if exit_code == 0 else "\n⚠️ Lab finished with errors")
    sys.exit(exit_code)
