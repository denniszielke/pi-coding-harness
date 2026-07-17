"""
Azure Container Apps Sandboxes - Pi Coding Harness

Boots an Ubuntu sandbox, installs the `pi` coding agent
(@earendil-works/pi-coding-agent) plus the GitHub CLI, clones a configurable
GitHub repo, switches to deny-default egress (only GitHub, package registries
and the chosen LLM provider allowed), configures git credentials inside the
sandbox via ~/.netrc, runs `pi` non-interactively on a natural-language task,
then commits, pushes and opens a pull request.

Why pi + ACA Sandboxes?
  Pi is a minimal terminal coding harness. In non-interactive print mode
  (`pi -p`) it runs its tools (read / write / edit / bash / grep / find / ls)
  with no permission popups — it expects to be run inside a container. ACA
  Sandboxes provide exactly that: an isolated, stateful, microVM-style
  execution boundary. The dangerous part (repo checkout, generated code,
  dependency restore, tests, shell commands) stays inside the sandbox.

Two independent credentials are injected, both living ONLY inside the
ephemeral sandbox:
  1. GitHub PAT  — for git clone / push and `gh pr create`.
     * ~/.netrc lets git authenticate over HTTPS silently.
     * GH_TOKEN env var lets the gh CLI authenticate.
  2. LLM provider API key — for pi's model calls (Anthropic / OpenAI / Google).
     Exported into the sandbox profile; pi reads it from the environment.

The sandbox is deleted on exit.

Configuration (.env or environment variables):
  PAT                       GitHub PAT with repo + workflow scopes (required)
  GITHUB_REPO               "owner/repo"  (required)
  GITHUB_BRANCH             branch to push to    (default: pi-<run_id>)
  GITHUB_BASE_BRANCH        branch to clone from (default: main)
  CODING_PROMPT             natural-language task for pi
  PI_PROVIDER               anthropic | openai | google | azure  (default: anthropic)
  PI_MODEL                  optional model pattern/id passed to `pi --model`
  ANTHROPIC_API_KEY         API key when PI_PROVIDER=anthropic
  OPENAI_API_KEY            API key when PI_PROVIDER=openai
  GEMINI_API_KEY            API key when PI_PROVIDER=google
  EGRESS_EXTRA_HOSTS        extra allowed egress hosts (space/comma separated)
  RESOURCE_GROUP_NAME       Azure resource group  (default: aca-sandboxes-rg)
  SANDBOX_GROUP_NAME        sandbox group name    (default: pi-coding)
  LOCATION                  Azure region          (default: westus3)

Azure OpenAI / Foundry (PI_PROVIDER=azure):
  Reads the resource coordinates already present in the project's .env:
  AZURE_AI_PROJECT_ENDPOINT the Foundry project endpoint, e.g.
                            https://<res>.services.ai.azure.com/api/projects/<proj>
                            (preferred; normalized to the account's /openai/v1)
  AZURE_OPENAI_ENDPOINT     direct Azure OpenAI endpoint, used if no project
                            endpoint is set (or set AZURE_OPENAI_BASE_URL to
                            override both)
  AZURE_AI_MODEL_DEPLOYMENT_NAME
                            model deployment name, used as the pi model id
                            (falls back to AZURE_OPENAI_DEPLOYMENT /
                            AZURE_OPENAI_CHAT_DEPLOYMENT_NAME)
  AZURE_AI_PROJECT_ID       Foundry project ARM id; the account scope for the
                            role grant is derived from it (or set
                            AZURE_OPENAI_ACCOUNT_RESOURCE_ID explicitly)
  AZURE_OPENAI_API          openai-responses (default) | openai-completions
  AZURE_OPENAI_API_KEY      optional; if set, uses key auth instead of MI
  AZURE_MANAGED_IDENTITY_CLIENT_ID
                            optional client id to select a user-assigned MI
                            (default: the sandbox group's SystemAssigned MI)
  AZURE_MANAGED_IDENTITY_RESOURCE_ID
                            optional ARM id of a pre-provisioned user-assigned
                            MI. When set, it is attached to the sandbox group
                            and role assignment is skipped (assumed pre-granted
                            by scripts/deploy_managed_identity.sh).

  With MI (the default when no API key is given) the harness enables a
  SystemAssigned managed identity on the sandbox group, grants it access to
  the deployment, and configures pi to authenticate with a short-lived Entra
  token (Authorization: Bearer) fetched from inside the sandbox — no API key.

Usage:
  python demo/05-pi-coding.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.containerapps.sandbox import (
    SandboxGroupManagementClient,
    SandboxGroupClient,
    endpoint_for_region,
)

# ── Load configuration ────────────────────────────────────────────────────────
# Resolve .env from the project root (one level above demo/) regardless of CWD,
# and override any existing shell env vars so the file values always win.
_env_file = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(_env_file, override=True)

# ── LLM provider selection ────────────────────────────────────────────────────
# pi authenticates to a model provider. For the API-key providers below, pi
# reads the key from an environment variable. For "azure" (Azure OpenAI /
# Foundry-hosted deployments), pi is configured through a models.json custom
# provider that authenticates either with an API key or — the focus of this
# harness — an Entra ID access token obtained from a managed identity that has
# been granted the "Cognitive Services OpenAI User" role on the deployment.
PROVIDER_CONFIG: dict[str, dict[str, tuple[str, ...] | str]] = {
    "anthropic": {"key_env": "ANTHROPIC_API_KEY", "hosts": ("api.anthropic.com",)},
    "openai":    {"key_env": "OPENAI_API_KEY",    "hosts": ("api.openai.com",)},
    "google":    {"key_env": "GEMINI_API_KEY",    "hosts": ("generativelanguage.googleapis.com",)},
}

COGNITIVE_ROLE_NAME = "Cognitive Services OpenAI User"

PI_PROVIDER = os.getenv("PI_PROVIDER", "anthropic").strip().lower()
IS_AZURE = PI_PROVIDER == "azure"
if not IS_AZURE and PI_PROVIDER not in PROVIDER_CONFIG:
    sys.exit(
        f"❌ Unsupported PI_PROVIDER '{PI_PROVIDER}'. "
        f"Choose one of: {', '.join(PROVIDER_CONFIG)}, azure."
    )

PI_MODEL = os.getenv("PI_MODEL", "").strip()


def _normalize_azure_base_url(raw: str) -> str:
    """Return the OpenAI-compatible v1 base URL for an Azure OpenAI / Foundry
    endpoint.

    Accepts:
      - https://res.openai.azure.com                 -> …/openai/v1
      - https://res.services.ai.azure.com            -> …/openai/v1
      - https://res.services.ai.azure.com/api/projects/<proj>
                                                     -> https://res.services.ai.azure.com/openai/v1
    The Foundry project endpoint (…/api/projects/<proj>) is a data-plane URL;
    model deployments are served by the account's OpenAI v1 route, so the
    project segment is stripped back to the account origin.
    """
    url = raw.strip().rstrip("/")
    if not url:
        return ""
    # Foundry project endpoint -> account origin (deployments live on the account).
    if "/api/projects/" in url:
        parsed = urlparse(url)
        url = f"{parsed.scheme}://{parsed.netloc}"
    if url.endswith("/openai/v1"):
        return url
    if url.endswith("/openai"):
        return url + "/v1"
    return url + "/openai/v1"


# Defaults for the API-key providers; overwritten below for Azure.
_key_env = ""
LLM_API_KEY = ""
PROVIDER_HOSTS: tuple[str, ...] = ()

# Azure-only configuration (populated when IS_AZURE).
AZURE_BASE_URL = ""
AZURE_DEPLOYMENT = ""
AZURE_API = ""
AZURE_API_KEY = ""
AZURE_USE_MI = False
AZURE_ACCOUNT_RESOURCE_ID = ""
AZURE_MI_CLIENT_ID = ""
AZURE_MI_RESOURCE_ID = ""

if IS_AZURE:
    # Align with the resource coordinates already present in .env. Prefer the
    # Foundry project endpoint (AZURE_AI_PROJECT_ENDPOINT) when set, then the
    # direct Azure OpenAI endpoint; AZURE_OPENAI_BASE_URL overrides both.
    _raw_base = (
        os.getenv("AZURE_OPENAI_BASE_URL", "").strip()
        or os.getenv("AZURE_AI_PROJECT_ENDPOINT", "").strip()
        or os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()
    )
    AZURE_BASE_URL = _normalize_azure_base_url(_raw_base)
    if not AZURE_BASE_URL:
        sys.exit(
            "❌ Azure endpoint is not set. Set AZURE_AI_PROJECT_ENDPOINT or "
            "AZURE_OPENAI_ENDPOINT (or AZURE_OPENAI_BASE_URL), e.g. "
            "'https://my-res.services.ai.azure.com/api/projects/my-project'."
        )
    AZURE_DEPLOYMENT = (
        os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip()
        or os.getenv("AZURE_AI_MODEL_DEPLOYMENT_NAME", "").strip()
        or os.getenv("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME", "").strip()
    )
    if not AZURE_DEPLOYMENT:
        sys.exit(
            "❌ Model deployment is not set. Set AZURE_AI_MODEL_DEPLOYMENT_NAME "
            "(or AZURE_OPENAI_DEPLOYMENT)."
        )
    # openai-responses (default, matches pi's built-in Azure provider) or openai-completions.
    AZURE_API = os.getenv("AZURE_OPENAI_API", "openai-responses").strip()
    AZURE_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
    # Managed-identity auth is the default; supplying an API key opts out of it.
    AZURE_USE_MI = not AZURE_API_KEY
    # Account scope for the RBAC grant: explicit override, else derived from the
    # Foundry project id in .env (strip the trailing /projects/<name>).
    AZURE_ACCOUNT_RESOURCE_ID = os.getenv("AZURE_OPENAI_ACCOUNT_RESOURCE_ID", "").strip()
    if not AZURE_ACCOUNT_RESOURCE_ID:
        _project_id = os.getenv("AZURE_AI_PROJECT_ID", "").strip()
        if "/projects/" in _project_id:
            AZURE_ACCOUNT_RESOURCE_ID = _project_id.split("/projects/", 1)[0]
    AZURE_MI_CLIENT_ID = os.getenv("AZURE_MANAGED_IDENTITY_CLIENT_ID", "").strip()
    # ARM id of a pre-provisioned user-assigned managed identity (see
    # scripts/deploy_managed_identity.sh). When set, it is attached to the
    # sandbox group and roles are assumed to be pre-assigned.
    AZURE_MI_RESOURCE_ID = os.getenv("AZURE_MANAGED_IDENTITY_RESOURCE_ID", "").strip()
    # pi selects the deployment by model id.
    PI_MODEL = AZURE_DEPLOYMENT
    # Egress: the specific endpoint host plus the Azure AI / Entra families.
    _azure_host = urlparse(AZURE_BASE_URL).netloc
    PROVIDER_HOSTS = (
        _azure_host,
        "*.openai.azure.com",
        "*.cognitiveservices.azure.com",
        "*.ai.azure.com",
    )
    if AZURE_USE_MI:
        PROVIDER_HOSTS += ("login.microsoftonline.com", "*.identity.azure.net")
else:
    _key_env = PROVIDER_CONFIG[PI_PROVIDER]["key_env"]  # type: ignore[assignment]
    LLM_API_KEY = os.getenv(_key_env, "")
    if not LLM_API_KEY:
        sys.exit(
            f"❌ {_key_env} is not set (required for PI_PROVIDER='{PI_PROVIDER}').\n"
            f"   Add it to .env or export it as an env var."
        )
    PROVIDER_HOSTS = PROVIDER_CONFIG[PI_PROVIDER]["hosts"]  # type: ignore[assignment]

# ── GitHub credentials ────────────────────────────────────────────────────────
PAT = os.getenv("PAT", "")
if not PAT:
    sys.exit("❌ PAT is not set. Add it to .env or export it as an env var.")

GITHUB_REPO = os.getenv("GITHUB_REPO", "")
if not GITHUB_REPO:
    sys.exit("❌ GITHUB_REPO is not set (e.g. 'myuser/myrepo'). Add it to .env.")

run_id = uuid.uuid4().hex[:8]

GITHUB_BASE_BRANCH = os.getenv("GITHUB_BASE_BRANCH", "main")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", f"pi-{run_id}")
CODING_PROMPT = os.getenv(
    "CODING_PROMPT",
    "Read task.md if present. Review the codebase, fix any obvious bugs or "
    "style issues, add a CHANGES.md file listing what you changed, then run "
    "the project's checks (tests / lint) if any exist.",
)
RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
SANDBOX_GROUP_NAME = os.getenv("SANDBOX_GROUP_NAME", "pi-coding")
LOCATION = os.getenv("LOCATION", "westus3")

# Extra egress hosts the agent is allowed to reach (e.g. for fetching external
# files referenced in the prompt). Space- or comma-separated list of hostnames
# or glob patterns. Set EGRESS_EXTRA_HOSTS in .env to override.
_extra_raw = os.getenv("EGRESS_EXTRA_HOSTS", "*.microsoft.com")
EGRESS_EXTRA_HOSTS: tuple[str, ...] = tuple(
    h.strip() for h in _extra_raw.replace(",", " ").split() if h.strip()
)

lab_labels = {"scenario": "pi-coding", "run": run_id}

# ── Host families that must be reachable once egress is locked down ───────────
ALLOW_HOSTS = (
    # GitHub — gh CLI, git clone/push
    "*.github.com",
    "*.githubusercontent.com",
    "gh.io",
    "*.github.io",
    "*.githubassets.com",
    # npm — pi is installed from the npm registry
    "*.npmjs.com",
    "registry.npmjs.org",
    # pi.dev — pi install script, version check, model catalog refresh
    "pi.dev",
    "*.pi.dev",
    # Python packaging — pip bootstrap + PyPI package downloads (repo venv)
    "bootstrap.pypa.io",
    "pypi.org",
    "*.pypi.org",
    "files.pythonhosted.org",
    # Ubuntu apt — installing system packages
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "*.ubuntu.com",
    # Node.js — NodeSource apt repo (pi runtime)
    "deb.nodesource.com",
    # uv / Astral toolchain installer
    "astral.sh",
    "*.astral.sh",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _exec_check(sandbox, cmd: str, *, label: str = "") -> str:
    """Run cmd in the sandbox; raise on non-zero exit and return stdout."""
    r = sandbox.exec(cmd)
    if r.exit_code != 0:
        tag = f" [{label}]" if label else ""
        raise RuntimeError(
            f"sandbox exec failed{tag}: exit={r.exit_code}\n"
            f"  cmd : {cmd!r}\n"
            f"  out : {(r.stdout or '')[:400]}\n"
            f"  err : {(r.stderr or '')[:400]}"
        )
    return (r.stdout or "").strip()


def _wait_exec_up(sandbox, *, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if sandbox.exec("true").exit_code == 0:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("sandbox exec endpoint did not come up in time")


def _portal_url(sub: str, rg: str, sg: str, sandbox_id: str) -> str:
    return (
        f"https://sandboxes.azure.com/sandbox-groups/{sub}/{rg}/{sg}"
        f"/sandboxes/{sandbox_id}"
    )


def _wait_for_group_principal(mgmt, group_name: str, *, timeout: float = 60.0) -> str:
    """Return the principalId of a sandbox group's SystemAssigned managed
    identity, waiting for it to appear after the identity is enabled."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        identity = getattr(mgmt.get_group(group_name), "identity", None) or {}
        pid = identity.get("principalId") if isinstance(identity, dict) else None
        if pid:
            return pid
        time.sleep(2)
    raise RuntimeError(f"sandbox group '{group_name}' has no managed-identity principalId")


def _assign_role_with_retry(auth_client, scope: str, role_name: str, principal_id: str) -> None:
    """Assign a built-in role to a principal at a scope, retrying while a
    brand-new managed-identity principal replicates through Entra ID."""
    role_def = next(
        auth_client.role_definitions.list(scope, filter=f"roleName eq '{role_name}'"),
        None,
    )
    if role_def is None:
        raise RuntimeError(f"role '{role_name}' not found at scope {scope}")
    last_exc: Exception | None = None
    for _ in range(12):
        try:
            auth_client.role_assignments.create(scope, str(uuid.uuid4()), {
                "role_definition_id": role_def.id,
                "principal_id": principal_id,
                "principal_type": "ServicePrincipal",
            })
            return
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "RoleAssignmentExists" in msg or "Conflict" in msg:
                return
            if "PrincipalNotFound" in msg or "does not exist in the directory" in msg:
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise RuntimeError(f"role grant never succeeded: {last_exc}")


def _configure_pi_azure(sandbox) -> None:
    """Write ~/.pi/agent/models.json (and, for managed identity, a token
    helper) so pi can call the Azure OpenAI / Foundry deployment.

    - Managed identity: a short-lived Entra token is fetched from inside the
      sandbox and sent as `Authorization: Bearer <token>` (authHeader=true).
    - API key: sent in the Azure-native `api-key` header.
    """
    sandbox.exec("mkdir -p /root/.pi/agent")

    provider_cfg: dict = {
        "baseUrl": AZURE_BASE_URL,
        "api": AZURE_API,
        "models": [
            {"id": AZURE_DEPLOYMENT, "name": AZURE_DEPLOYMENT, "input": ["text", "image"]}
        ],
    }

    if AZURE_USE_MI:
        # Token helper: uses the sandbox's managed identity to mint a
        # Cognitive Services access token. pi runs this per request.
        token_script = (
            "#!/bin/bash\n"
            "exec /root/.pitoken/bin/python - <<'PY'\n"
            "import os\n"
            "from azure.identity import ManagedIdentityCredential\n"
            "cid = os.environ.get('AZURE_MI_CLIENT_ID') or None\n"
            "cred = ManagedIdentityCredential(client_id=cid) if cid else ManagedIdentityCredential()\n"
            "print(cred.get_token('https://cognitiveservices.azure.com/.default').token, end='')\n"
            "PY\n"
        )
        sandbox.write_file("/root/get_aoai_token.sh", token_script)
        sandbox.exec("chmod +x /root/get_aoai_token.sh")
        provider_cfg["apiKey"] = "!/root/get_aoai_token.sh"
        provider_cfg["authHeader"] = True  # Authorization: Bearer <token>
        if AZURE_MI_CLIENT_ID:
            for rc in ("~/.bashrc", "~/.profile"):
                sandbox.exec(f"echo 'export AZURE_MI_CLIENT_ID={AZURE_MI_CLIENT_ID}' >> {rc}")
    else:
        provider_cfg["apiKey"] = "$AZURE_OPENAI_API_KEY"
        provider_cfg["headers"] = {"api-key": "$AZURE_OPENAI_API_KEY"}
        for rc in ("~/.bashrc", "~/.profile"):
            sandbox.exec(f"echo 'export AZURE_OPENAI_API_KEY={AZURE_API_KEY}' >> {rc}")

    models_json = {"providers": {"azure-foundry": provider_cfg}}
    sandbox.write_file("/root/.pi/agent/models.json", json.dumps(models_json, indent=2))


def _exec_stream(
    sandbox,
    cmd: str,
    *,
    poll_interval: float = 2.0,
    label: str = "",
) -> int:
    """Run cmd in the background and stream its output to stdout by polling
    a log file inside the sandbox. Returns the process exit code.

    Strategy:
      1. Write the command to a temp script via write_file (avoids shell-quoting
         nightmares when the command contains single/double quotes).
      2. Launch it with `bash <script> >log 2>&1; echo $? >done &`.
      3. Poll `awk 'NR>N' log` every poll_interval seconds and print new lines.
      4. Stop when the done-file appears and contains the exit code.
    """
    tag = uuid.uuid4().hex[:8]
    script_path = f"/tmp/stream_{tag}.sh"
    log_path = f"/tmp/stream_{tag}.log"
    done_path = f"/tmp/stream_{tag}.done"

    # Write the command as a shell script so no quoting escaping is needed.
    sandbox.write_file(script_path, f"#!/bin/bash\n{cmd}\n")
    sandbox.exec(f"chmod +x {script_path}")
    # Wrap in `bash -c '...' &` so the ENTIRE subshell is backgrounded and
    # sandbox.exec() returns immediately instead of waiting for the process.
    sandbox.exec(
        f"bash -c 'bash {script_path} >{log_path} 2>&1; echo $? >{done_path}' &"
    )

    lines_shown = 0
    while True:
        time.sleep(poll_interval)

        # Print any lines we haven't shown yet.
        r = sandbox.exec(f"awk 'NR>{lines_shown}' {log_path} 2>/dev/null || true")
        if r.stdout:
            print(r.stdout, end="", flush=True)
            lines_shown += r.stdout.count("\n")

        # Check whether the process finished.
        done_r = sandbox.exec(f"cat {done_path} 2>/dev/null || true")
        exit_str = (done_r.stdout or "").strip()
        if exit_str and exit_str.lstrip("-").isdigit():
            # Final flush — catch any output written after the last poll.
            r = sandbox.exec(f"awk 'NR>{lines_shown}' {log_path} 2>/dev/null || true")
            if r.stdout:
                print(r.stdout, end="", flush=True)
            return int(exit_str)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    # -- Azure subscription info -----------------------------------------------
    try:
        proc = subprocess.run(
            "az account show -o json",
            capture_output=True, text=True, check=True, shell=True,
        )
        subscription = json.loads(proc.stdout)
        subscription_id = subscription["id"]
    except subprocess.CalledProcessError as e:
        sys.exit(f"❌ az CLI not logged in. Run `az login` first.\n{e.stderr}")

    print(f"🧪 Scenario:              pi-coding  (run={run_id})")
    print(f"🤖 Coding agent:          pi ({PI_PROVIDER}{'/' + PI_MODEL if PI_MODEL else ''})")
    if IS_AZURE:
        print(f"🔐 Azure auth:            {'managed identity' if AZURE_USE_MI else 'API key'}")
        print(f"🚀 Deployment:            {AZURE_DEPLOYMENT}  @ {AZURE_BASE_URL}")
    print(f"👤 User:                  {subscription['user']['name']}")
    print(f"🔑 Subscription:          {subscription['name']} ({subscription_id})")
    print(f"🌍 Region:                {LOCATION}")
    print(f"📁 Resource group:        {RESOURCE_GROUP_NAME}")
    print(f"📦 Sandbox group:         {SANDBOX_GROUP_NAME}")
    print(f"🐙 Target repo:           {GITHUB_REPO}")
    print(f"🌿 Base / push branch:    {GITHUB_BASE_BRANCH} → {GITHUB_BRANCH}")
    print(f"📝 Prompt:                {CODING_PROMPT[:80]}{'…' if len(CODING_PROMPT) > 80 else ''}")

    cli_credential = AzureCliCredential()
    resource_mgmt_client = ResourceManagementClient(cli_credential, subscription_id)
    sandboxgroup_mgmt_client = SandboxGroupManagementClient(
        cli_credential,
        subscription_id=subscription_id,
        resource_group=RESOURCE_GROUP_NAME,
    )

    # -- Resource group --------------------------------------------------------
    print("\n### Step 1: Resource group + sandbox group")
    if resource_mgmt_client.resource_groups.check_existence(RESOURCE_GROUP_NAME):
        rg = resource_mgmt_client.resource_groups.get(RESOURCE_GROUP_NAME)
        print(f"♻️  Using existing RG: {rg.name} ({rg.location})")
    else:
        rg = resource_mgmt_client.resource_groups.create_or_update(
            RESOURCE_GROUP_NAME, {"location": LOCATION, "tags": lab_labels}
        )
        print(f"✅ Created RG: {rg.name} ({rg.location})")

    existing = next(
        (g for g in sandboxgroup_mgmt_client.list_groups() if g.name == SANDBOX_GROUP_NAME),
        None,
    )
    need_mi = IS_AZURE and AZURE_USE_MI
    # User-assigned (pre-provisioned) vs SystemAssigned (created here) identity.
    if need_mi and AZURE_MI_RESOURCE_ID:
        identity_arg: dict = {
            "type": "UserAssigned",
            "userAssignedIdentities": {AZURE_MI_RESOURCE_ID: {}},
        }
    else:
        identity_arg = {"type": "SystemAssigned"}

    if existing and not need_mi:
        print(f"♻️  Using existing sandbox group: {SANDBOX_GROUP_NAME}")
    elif need_mi:
        # The managed identity must be attached to the group *before* the
        # sandbox is created so the sandbox inherits it. begin_create_group is
        # create-or-update, so this also attaches the identity to an existing
        # group.
        if AZURE_MI_RESOURCE_ID:
            sandboxgroup_mgmt_client.begin_create_group(
                SANDBOX_GROUP_NAME, rg.location, identity=identity_arg,
            ).result()
            print(
                f"✅ Sandbox group ready with user-assigned managed identity: {SANDBOX_GROUP_NAME}\n"
                f"   {AZURE_MI_RESOURCE_ID}"
            )
        else:
            ident = (
                (sandboxgroup_mgmt_client.get_group(SANDBOX_GROUP_NAME).identity or {})
                if existing else {}
            )
            if isinstance(ident, dict) and ident.get("principalId"):
                print(f"♻️  Using existing sandbox group (managed identity): {SANDBOX_GROUP_NAME}")
            else:
                sandboxgroup_mgmt_client.begin_create_group(
                    SANDBOX_GROUP_NAME, rg.location, identity=identity_arg,
                ).result()
                print(f"✅ Sandbox group ready with SystemAssigned managed identity: {SANDBOX_GROUP_NAME}")
    else:
        sandboxgroup_mgmt_client.create_group(
            SANDBOX_GROUP_NAME, location=rg.location, tags=lab_labels
        )
        print(f"✅ Created sandbox group: {SANDBOX_GROUP_NAME}")

    sandboxgroup = sandboxgroup_mgmt_client.get_group(SANDBOX_GROUP_NAME)

    # -- Data-plane role assignment --------------------------------------------
    print("\n### Step 2: Data-plane access")
    auth_client = AuthorizationManagementClient(cli_credential, subscription_id)
    role_name = "Container Apps SandboxGroup Data Owner"
    scope = f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP_NAME}"
    role_def = next(auth_client.role_definitions.list(scope, filter=f"roleName eq '{role_name}'"))

    proc = subprocess.run(
        "az ad signed-in-user show --query id -o tsv",
        capture_output=True, text=True, check=True, shell=True,
    )
    user_principal_id = proc.stdout.strip()
    try:
        auth_client.role_assignments.create(scope, uuid.uuid4(), {
            "role_definition_id": role_def.id,
            "principal_id": user_principal_id,
            "principal_type": "User",
        })
        print(f"✅ Assigned '{role_name}'. Waiting 60s for propagation...")
        time.sleep(60)
    except Exception as ex:
        if "RoleAssignmentExists" in str(ex) or "Conflict" in str(ex):
            print(f"♻️  '{role_name}' already assigned.")
        else:
            raise

    # -- Grant the sandbox MI access to the Azure OpenAI deployment ------------
    if IS_AZURE and AZURE_USE_MI:
        print("\n### Step 2b: Managed identity access to the model deployment")
        if AZURE_MI_RESOURCE_ID:
            # Pre-provisioned user-assigned identity (deploy_managed_identity.sh
            # already granted the roles) — nothing to do here.
            print("  ✅ Using pre-provisioned user-assigned identity; roles assumed granted.")
        else:
            mi_principal_id = _wait_for_group_principal(sandboxgroup_mgmt_client, SANDBOX_GROUP_NAME)
            print(f"  🆔 Sandbox group MI principalId: {mi_principal_id}")
            if AZURE_ACCOUNT_RESOURCE_ID:
                aoai_sub = AZURE_ACCOUNT_RESOURCE_ID.split("/")[2]
                aoai_auth_client = (
                    auth_client if aoai_sub == subscription_id
                    else AuthorizationManagementClient(cli_credential, aoai_sub)
                )
                _assign_role_with_retry(
                    aoai_auth_client, AZURE_ACCOUNT_RESOURCE_ID, COGNITIVE_ROLE_NAME, mi_principal_id,
                )
                print(f"  ✅ Assigned '{COGNITIVE_ROLE_NAME}' on the Azure OpenAI account.")
                print("  ⏳ Waiting 30s for RBAC propagation...")
                time.sleep(30)
            else:
                print(
                    "  ⚠️  AZURE_OPENAI_ACCOUNT_RESOURCE_ID not set — skipping role assignment.\n"
                    f"     Ensure the MI (principalId {mi_principal_id}) already has\n"
                    f"     '{COGNITIVE_ROLE_NAME}' on the target Azure OpenAI resource."
                )

    # -- Sandbox client --------------------------------------------------------
    client = SandboxGroupClient(
        endpoint_for_region(sandboxgroup.location),
        cli_credential,
        subscription_id=subscription_id,
        resource_group=RESOURCE_GROUP_NAME,
        sandbox_group=SANDBOX_GROUP_NAME,
    )

    sandbox = None
    try:
        # -- Boot sandbox ------------------------------------------------------
        print("\n### Step 3: Boot sandbox (ubuntu, 2 CPU, 4 GB)")
        sandbox = client.begin_create_sandbox(
            disk="ubuntu",
            cpu="2000m",
            memory="4096Mi",
            labels=lab_labels,
        ).result()
        print(f"✅ Sandbox ready: {sandbox.sandbox_id}")
        print(f"   Portal: {_portal_url(subscription_id, RESOURCE_GROUP_NAME, SANDBOX_GROUP_NAME, sandbox.sandbox_id)}")

        print("⏳ Waiting for exec endpoint...")
        _wait_exec_up(sandbox)

        # -- Install toolchain (under default-allow egress) --------------------
        print("\n### Step 4: Install toolchain  [egress: default ALLOW]")

        print("  → git, curl, jq")
        _exec_check(
            sandbox,
            "apt-get update -qq && apt-get install -y -qq git curl jq",
            label="apt",
        )

        print("  → Node.js 22 + npm (pi runtime)")
        _exec_check(
            sandbox,
            "curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && "
            "apt-get install -y -qq nodejs",
            label="node-install",
        )

        print("  → GitHub CLI")
        _exec_check(
            sandbox,
            (
                "curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg"
                " -o /usr/share/keyrings/githubcli-archive-keyring.gpg && "
                "chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg && "
                # Hardcode amd64 — sandbox is always x86_64; avoid $() inside single
                # quotes which would be written literally and break the apt source entry.
                'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg]'
                ' https://cli.github.com/packages stable main"'
                " > /etc/apt/sources.list.d/github-cli.list && "
                "apt-get update -qq && apt-get install -y -qq gh"
            ),
            label="gh-install",
        )

        print("  → pi coding agent (npm -g @earendil-works/pi-coding-agent)")
        _exec_check(
            sandbox,
            "npm install -g --ignore-scripts @earendil-works/pi-coding-agent",
            label="pi-install",
        )
        pi_version = _exec_check(sandbox, "pi --version", label="pi-version")
        print(f"  ✅ pi installed: {pi_version}")

        # Python toolchain — installed now, while egress is still default-ALLOW,
        # so the venv build in Step 7.5 (after lockdown) needs no apt access.
        print("  → Python venv + pip (repo checks / pi bash tool)")
        _exec_check(
            sandbox,
            "apt-get install -y -qq python3-pip python3-venv",
            label="python-venv-apt",
        )

        if IS_AZURE and AZURE_USE_MI:
            print("  → azure-identity (managed-identity token helper for pi)")
            _exec_check(sandbox, "python3 -m venv /root/.pitoken", label="token-venv-create")
            _exec_check(sandbox, "/root/.pitoken/bin/pip install -q azure-identity", label="token-venv-install")

        # -- Write credentials into sandbox (ephemeral) -----------------------
        print("\n### Step 5: Configure credentials inside sandbox")

        # ~/.netrc gives git push / clone silent Basic-auth over HTTPS
        _exec_check(
            sandbox,
            f"printf 'machine github.com\\n  login x-access-token\\n  password {PAT}\\n' > ~/.netrc && chmod 600 ~/.netrc",
            label="netrc",
        )

        # GH_TOKEN makes gh CLI work without interactive login.
        _exec_check(
            sandbox,
            f"echo 'export GH_TOKEN={PAT}' >> ~/.bashrc && "
            f"echo 'export GH_TOKEN={PAT}' >> ~/.profile",
            label="gh-token-env",
        )

        # Configure pi's model provider.
        if IS_AZURE:
            _configure_pi_azure(sandbox)
            print(f"  ✅ pi configured for Azure ({AZURE_API}) → deployment '{AZURE_DEPLOYMENT}'")
            if AZURE_USE_MI:
                print("  🔍 Verifying managed-identity token for Azure OpenAI...")
                tok = sandbox.exec("/root/get_aoai_token.sh | head -c 16")
                if tok.exit_code == 0 and (tok.stdout or "").strip():
                    print("  ✅ Managed identity issued a Cognitive Services token.")
                else:
                    print(f"  ⚠️  Token fetch failed: {(tok.stderr or tok.stdout or '')[:200]}")
        else:
            # API-key providers: pi reads the key from the environment.
            _exec_check(
                sandbox,
                f"echo 'export {_key_env}={LLM_API_KEY}' >> ~/.bashrc && "
                f"echo 'export {_key_env}={LLM_API_KEY}' >> ~/.profile",
                label="llm-key-env",
            )

        # Git user identity for commits
        _exec_check(sandbox, 'git config --global user.email "pi-agent@sandbox.local"', label="git-email")
        _exec_check(sandbox, 'git config --global user.name "Pi Coding Agent"', label="git-name")
        _exec_check(sandbox, "git config --global credential.helper store", label="git-cred")

        # Verify PAT works
        print("  🔍 Verifying GitHub PAT...")
        gh_user = _exec_check(
            sandbox,
            f"GH_TOKEN={PAT} gh api user --jq .login",
            label="gh-auth-check",
        )
        print(f"  ✅ Authenticated as GitHub user: {gh_user}")

        # -- Lock down egress --------------------------------------------------
        all_allow_hosts = ALLOW_HOSTS + PROVIDER_HOSTS + EGRESS_EXTRA_HOSTS
        print(
            f"\n### Step 6: Lock down egress  "
            f"[default: DENY → GitHub + {PI_PROVIDER} + {len(EGRESS_EXTRA_HOSTS)} extra host(s)]"
        )
        sandbox.set_egress_default("Deny")
        print(f"  → Allowing {len(all_allow_hosts)} host(s): {', '.join(all_allow_hosts)}")
        for host in all_allow_hosts:
            sandbox.add_egress_host_rule(host, action="Allow")
        print("  ✅ Egress locked to GitHub, package registries and the LLM provider")

        # -- Clone target repo -------------------------------------------------
        print(f"\n### Step 7: Clone {GITHUB_REPO}  (branch: {GITHUB_BASE_BRANCH})")
        repo_dir = f"/root/{GITHUB_REPO.split('/')[-1]}"
        clone_url = f"https://github.com/{GITHUB_REPO}.git"
        _exec_check(
            sandbox,
            f"git clone --branch {GITHUB_BASE_BRANCH} --depth 50 {clone_url} {repo_dir}",
            label="git-clone",
        )
        print(f"  ✅ Cloned into {repo_dir}")

        # Create and switch to the push branch
        _exec_check(
            sandbox,
            f"git -C {repo_dir} checkout -b {GITHUB_BRANCH}",
            label="git-checkout",
        )
        print(f"  🌿 On new branch: {GITHUB_BRANCH}")

        # -- Pre-build Python environment in the repo -------------------------
        # If the repo is a Python project, pre-build a venv and auto-activate it
        # in future shells so pi can simply run `python` / `pytest` from PATH.
        # The python3-venv/pip apt packages were installed in Step 4 (before the
        # egress lockdown); here we only need PyPI, which stays allowed.
        print("\n### Step 7.5: Pre-build Python environment")
        has_reqs = sandbox.exec(f"test -f {repo_dir}/requirements.txt").exit_code == 0
        _exec_check(
            sandbox,
            f"python3 -m venv {repo_dir}/.venv",
            label="venv-create",
        )
        if has_reqs:
            _exec_check(
                sandbox,
                f"{repo_dir}/.venv/bin/pip install -r {repo_dir}/requirements.txt pytest -q",
                label="venv-install-reqs",
            )
            print("  ✅ Venv created and requirements installed")
        else:
            _exec_check(
                sandbox,
                f"{repo_dir}/.venv/bin/pip install pytest -q",
                label="venv-install-pytest",
            )
            print("  ✅ Venv created (no requirements.txt found)")
        _exec_check(
            sandbox,
            f"echo 'source {repo_dir}/.venv/bin/activate' >> ~/.bashrc && "
            f"echo 'source {repo_dir}/.venv/bin/activate' >> ~/.profile",
            label="venv-autoactivate",
        )
        print("  ✅ Venv auto-activated in ~/.bashrc and ~/.profile")

        # -- Run pi ------------------------------------------------------------
        print("\n### Step 8: Run pi coding agent  [non-interactive print mode]")
        print(f"  📝 Prompt: {CODING_PROMPT}")
        print()

        # Write the prompt to a file OUTSIDE the repo so it is not committed,
        # and feed it to pi via command substitution (avoids all shell-quoting
        # issues with arbitrary prompt text).
        sandbox.write_file("/root/pi_prompt.txt", CODING_PROMPT)

        # `-a` trusts project-local files for this run; `-p` is print mode
        # (non-interactive — pi runs its tools with no permission popups).
        # `--offline` skips pi.dev startup calls now that egress is locked.
        # For Azure, qualify the model with our custom provider (provider/id)
        # so pi uses the azure-foundry provider from models.json instead of the
        # built-in azure-openai-responses provider (which expects an API key).
        if IS_AZURE:
            pi_model_ref = f"azure-foundry/{AZURE_DEPLOYMENT}"
        else:
            pi_model_ref = PI_MODEL
        model_flag = f"--model {pi_model_ref} " if pi_model_ref else ""
        pi_cmd = (
            f'pi --offline -a {model_flag}-p "$(cat /root/pi_prompt.txt)"'
        )
        # Credentials are already exported into the shell profile; also pass
        # them inline so `bash -lc` has them even if profile sourcing lags.
        env_prefix = f"GH_TOKEN={PAT}"
        if IS_AZURE:
            if AZURE_USE_MI and AZURE_MI_CLIENT_ID:
                env_prefix += f" AZURE_MI_CLIENT_ID={AZURE_MI_CLIENT_ID}"
            elif not AZURE_USE_MI:
                env_prefix += f" AZURE_OPENAI_API_KEY={AZURE_API_KEY}"
        else:
            env_prefix += f" {_key_env}={LLM_API_KEY}"
        agent_cmd = (
            f"cd {repo_dir} && {env_prefix} "
            f"bash -lc '{pi_cmd}'"
        )
        exit_code = _exec_stream(sandbox, agent_cmd, poll_interval=3.0, label="pi-agent")
        if exit_code != 0:
            print(f"  ⚠️  pi exited with code {exit_code}.")

        # -- Commit and push ---------------------------------------------------
        print(f"\n### Step 9: Commit & push → {GITHUB_BRANCH}")

        diff_check = sandbox.exec(f"git -C {repo_dir} status --porcelain")
        if not (diff_check.stdout or "").strip():
            print("  ℹ️  No changes detected — nothing to commit.")
        else:
            _exec_check(sandbox, f"git -C {repo_dir} add -A", label="git-add")
            _exec_check(
                sandbox,
                f'git -C {repo_dir} commit -m "chore: pi-agent changes (run={run_id})"',
                label="git-commit",
            )
            push_result = _exec_check(
                sandbox,
                f"git -C {repo_dir} push https://x-access-token:{PAT}@github.com/{GITHUB_REPO}.git {GITHUB_BRANCH}",
                label="git-push",
            )
            print(f"  ✅ Pushed branch: {GITHUB_BRANCH}")
            print(f"  🔗 Compare: https://github.com/{GITHUB_REPO}/compare/{GITHUB_BASE_BRANCH}...{GITHUB_BRANCH}")
            if push_result:
                print(f"     {push_result}")

            # Optionally open a PR via gh CLI
            pr_cmd = (
                f"GH_TOKEN={PAT} gh pr create "
                f"--repo {GITHUB_REPO} "
                f"--head {GITHUB_BRANCH} "
                f"--base {GITHUB_BASE_BRANCH} "
                f'--title "pi agent: run {run_id}" '
                f'--body "Automated changes from pi coding agent (run={run_id})\\n\\n'
                f'Provider: {PI_PROVIDER}{"/" + PI_MODEL if PI_MODEL else ""}\\n'
                f'Prompt: {CODING_PROMPT[:200]}"'
            )
            pr_r = sandbox.exec(pr_cmd)
            if pr_r.exit_code == 0:
                print(f"  🎉 PR created: {(pr_r.stdout or '').strip()}")
            else:
                print(f"  ℹ️  PR creation skipped (exit={pr_r.exit_code}): {(pr_r.stderr or '')[:200]}")

        print(f"\n✅ Done!  Branch '{GITHUB_BRANCH}' in {GITHUB_REPO}")

    finally:
        if sandbox is not None:
            print()
            print("=" * 72)
            print("Sandbox is still running. Inspect it at:")
            print(f"  {_portal_url(subscription_id, RESOURCE_GROUP_NAME, SANDBOX_GROUP_NAME, sandbox.sandbox_id)}")
            print()
            print("Or open an interactive shell with:")
            print(f"  aca sandbox shell --id {sandbox.sandbox_id}")
            print("=" * 72)
            try:
                input("\nPress Enter to delete the sandbox and exit… ")
            except (EOFError, KeyboardInterrupt):
                print()
            print(f"\n### Cleanup: deleting sandbox {sandbox.sandbox_id}…")
            try:
                sandbox.delete()
                print("  🗑️  Sandbox deleted.")
            except Exception as e:
                print(f"  ⚠️  Delete warning: {e}")
        else:
            # Interrupted before sandbox was created — sweep by label
            print(f"\n### Cleanup: sweeping leaked sandboxes (run={run_id})…")
            try:
                for sbx in client.list_sandboxes(labels={"run": run_id}):
                    try:
                        client.delete_sandbox(sbx.id)
                        print(f"  🗑️  Deleted {sbx.id}")
                    except Exception as e:
                        print(f"  ⚠️  {sbx.id}: {e}")
            except Exception as e:
                print(f"  ⚠️  Sweep failed: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
