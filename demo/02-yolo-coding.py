"""
Azure Container Apps Sandboxes - YOLO Coding Agent

Boots an Ubuntu sandbox, clones a configurable GitHub repo, installs the
GitHub CLI + Copilot extension, switches to deny-default egress (only GitHub
hosts allowed), configures git credentials inside the sandbox via ~/.netrc
so the coding agent can commit and push without any interactive prompts.

The PAT is read from the local .env file and injected into the sandbox
using two mechanisms:
  1. ~/.netrc  — lets git push/clone over HTTPS authenticate silently.
  2. GH_TOKEN env var written into the sandbox profile — lets gh CLI calls
     authenticate (list repos, create PRs, etc.).

Both live only inside the ephemeral sandbox container.  The sandbox is
deleted unconditionally on exit.

Configuration (.env or environment variables):
  PAT                       GitHub PAT with repo + workflow + read:user scopes
  GITHUB_REPO               "owner/repo"  (required)
  GITHUB_BRANCH             branch to push to   (default: yolo-<run_id>)
  GITHUB_BASE_BRANCH        branch to clone from (default: main)
  CODING_PROMPT             natural-language task for the coding agent
  RESOURCE_GROUP_NAME       Azure resource group  (default: aca-sandboxes-rg)
  SANDBOX_GROUP_NAME        sandbox group name    (default: yolo-coding)
  LOCATION                  Azure region          (default: westus3)

Usage:
  python demo/02-yolo-coding.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from dotenv import load_dotenv
from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.containerapps.sandbox import (
    SandboxGroupManagementClient,
    SandboxGroupClient,
    EgressHeader,
    endpoint_for_region,
)

# ── Load configuration ────────────────────────────────────────────────────────
# Resolve .env from the project root (one level above demo/) regardless of CWD,
# and override any existing shell env vars so the file values always win.
_env_file = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(_env_file, override=True)

PAT = os.getenv("PAT", "")
if not PAT:
    sys.exit("❌ PAT is not set. Add it to .env or export it as an env var.")
if PAT.startswith("ghp_"):
    sys.exit(
        "❌ Classic PAT detected (ghp_). The `copilot` binary requires a\n"
        "   Fine-Grained PAT. Create one at:\n"
        "   https://github.com/settings/tokens?type=beta\n"
        "   Required permissions: Contents (read/write), Metadata (read), Pull requests (read/write)"
    )

GITHUB_REPO = os.getenv("GITHUB_REPO", "")
if not GITHUB_REPO:
    sys.exit("❌ GITHUB_REPO is not set (e.g. 'myuser/myrepo'). Add it to .env.")

run_id = uuid.uuid4().hex[:8]

GITHUB_BASE_BRANCH = os.getenv("GITHUB_BASE_BRANCH", "main")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", f"yolo-{run_id}")
CODING_PROMPT = os.getenv(
    "CODING_PROMPT",
    "Review the codebase, fix any obvious bugs or style issues, add a "
    "CHANGES.md file listing what you changed, then commit and push.",
)
RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
SANDBOX_GROUP_NAME = os.getenv("SANDBOX_GROUP_NAME", "yolo-coding")
LOCATION = os.getenv("LOCATION", "westus3")

# Extra egress hosts the agent is allowed to reach (e.g. for fetching external
# files referenced in the prompt).  Space- or comma-separated list of hostnames
# or glob patterns. Set EGRESS_EXTRA_HOSTS in .env to override.
_extra_raw = os.getenv("EGRESS_EXTRA_HOSTS", "*.microsoft.com")
EGRESS_EXTRA_HOSTS: tuple[str, ...] = tuple(
    h.strip() for h in _extra_raw.replace(",", " ").split() if h.strip()
)

lab_labels = {"scenario": "yolo-coding", "run": run_id}

# Base64-encode PAT for git HTTPS Basic auth  (:PAT → no username needed)
PAT_B64 = base64.b64encode(f"x-access-token:{PAT}".encode()).decode()

# ── Host families that must be reachable ─────────────────────────────────────
ALLOW_HOSTS = (
    # GitHub — Copilot CLI, gh CLI, git clone/push
    "*.github.com",
    "*.githubusercontent.com",
    "gh.io",
    "*.github.io",
    "*.githubassets.com",
    "*.npmjs.com",          # gh extension installs pull from npm
    # Python packaging — pip bootstrap + PyPI package downloads
    "bootstrap.pypa.io",
    "pypi.org",
    "*.pypi.org",
    "files.pythonhosted.org",
    # Ubuntu apt — agent may install system packages
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "*.ubuntu.com",
    # uv / Astral toolchain installer
    "astral.sh",
    "*.astral.sh",
)

# Hosts that need an injected Authorization header (egress transform rules).
# IMPORTANT: do NOT add github.com here — *.github.com is covered by the plain
# Allow rule below, and a Basic-auth transform would conflict with git HTTPS.
# The three hosts below are the only ones Copilot CLI uses for auth.
INJECT_HOSTS: tuple[tuple[str, str, str], ...] = (
    ("api.github.com",                        "token",  "github-api-auth"),
    ("api.enterprise.githubcopilot.com",       "Bearer", "copilot-enterprise-auth"),
    ("telemetry.enterprise.githubcopilot.com", "Bearer", "copilot-telemetry-auth"),
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


def _exec_stream(
    sandbox,
    cmd: str,
    *,
    poll_interval: float = 2.0,
    label: str = "",
) -> int:
    """Run cmd in the background and stream its output to stdout by polling
    a log file inside the sandbox.  Returns the process exit code.

    Strategy:
      1. Write the command to a temp script via write_file (avoids shell-quoting
         nightmares when the command contains single/double quotes).
      2. Launch it with `bash <script> >log 2>&1; echo $? >done &`.
      3. Poll `awk 'NR>N' log` every poll_interval seconds and print new lines.
      4. Stop when the done-file appears and contains the exit code.
    """
    tag = uuid.uuid4().hex[:8]
    script_path = f"/tmp/stream_{tag}.sh"
    log_path    = f"/tmp/stream_{tag}.log"
    done_path   = f"/tmp/stream_{tag}.done"

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

def _assert_no_copilot_host_rule(sandbox) -> None:
    """Guard: a broad *.githubcopilot.com host-allow rule would bypass the
    transform injection and send requests unauthenticated."""
    policy = sandbox.get_egress_policy()
    for rule in getattr(policy, "host_rules", []) or []:
        pattern = getattr(rule, "pattern", "") or ""
        if "githubcopilot.com" in pattern:
            raise RuntimeError(
                "Egress policy has a host rule matching *.githubcopilot.com. "
                "This short-circuits the PAT-injection transforms. Remove it."
            )


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

    print(f"🧪 Scenario:              yolo-coding  (run={run_id})")
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
    if existing:
        print(f"♻️  Using existing sandbox group: {SANDBOX_GROUP_NAME}")
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

        print("  → GitHub Copilot coding-agent CLI")
        r = sandbox.exec(f"GH_TOKEN={PAT} timeout 180s bash -lc 'curl -fsSL https://gh.io/copilot-install | bash'")
        if r.exit_code != 0:
            print(f"  ⚠️  Copilot CLI install warning (non-fatal): {(r.stderr or r.stdout or '')[:300]}")
        else:
            print(f"  ✅ Copilot CLI installed: {(r.stdout or '').strip().splitlines()[-1] if (r.stdout or '').strip() else 'ok'}")

        # -- Write credentials into sandbox (ephemeral) -----------------------
        print("\n### Step 5: Configure git credentials inside sandbox")

        # ~/.netrc gives git push / clone silent Basic-auth over HTTPS
        _exec_check(
            sandbox,
            f"printf 'machine github.com\\n  login x-access-token\\n  password {PAT}\\n' > ~/.netrc && chmod 600 ~/.netrc",
            label="netrc",
        )

        # GH_TOKEN makes gh CLI work without interactive login
        _exec_check(
            sandbox,
            f"echo 'export GH_TOKEN={PAT}' >> ~/.bashrc && echo 'export GH_TOKEN={PAT}' >> ~/.profile",
            label="gh-token-env",
        )

        # Git user identity for commits
        _exec_check(sandbox, 'git config --global user.email "yolo-agent@sandbox.local"', label="git-email")
        _exec_check(sandbox, 'git config --global user.name "YOLO Coding Agent"', label="git-name")
        # Use netrc credential store
        _exec_check(sandbox, "git config --global credential.helper store", label="git-cred")

        # Verify PAT works
        print("  🔍 Verifying PAT...")
        gh_user = _exec_check(
            sandbox,
            f"GH_TOKEN={PAT} gh api user --jq .login",
            label="gh-auth-check",
        )
        print(f"  ✅ Authenticated as GitHub user: {gh_user}")

        # -- Lock down egress --------------------------------------------------
        all_allow_hosts = ALLOW_HOSTS + EGRESS_EXTRA_HOSTS
        print(f"\n### Step 6: Lock down egress  [default: DENY → GitHub + {len(EGRESS_EXTRA_HOSTS)} extra host(s)]")
        sandbox.set_egress_default("Deny")
        print(f"  → Allowing {len(all_allow_hosts)} host(s): {', '.join(all_allow_hosts)}")
        for host in all_allow_hosts:
            sandbox.add_egress_host_rule(host, action="Allow")

        print(f"  → Adding {len(INJECT_HOSTS)} PAT-injection transform rules")
        for host, scheme, name in INJECT_HOSTS:
            token_value = PAT_B64 if scheme == "Basic" else PAT
            sandbox.add_egress_transform_rule(
                host=host,
                headers=[EgressHeader(
                    operation="Set",
                    name="Authorization",
                    value=f"{scheme} {token_value}",
                )],
                name=name,
            )

        _assert_no_copilot_host_rule(sandbox)
        print("  ✅ Egress locked; footgun guard passed")

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
        # The Copilot agent's shell tool blocks running binaries via absolute
        # path (e.g. .venv/bin/python) without user confirmation — even with
        # --allow-all-tools.  Pre-building the venv here and auto-activating it
        # in ~/.bashrc means the agent always finds `python` / `pytest` in PATH
        # and never needs to resolve absolute venv paths itself.
        print(f"\n### Step 7.5: Pre-build Python environment")
        has_reqs = sandbox.exec(f"test -f {repo_dir}/requirements.txt").exit_code == 0
        _exec_check(
            sandbox,
            "apt-get install -y -qq python3-pip python3-venv",
            label="python-venv-apt",
        )
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
            print(f"  ✅ Venv created and requirements installed")
        else:
            _exec_check(
                sandbox,
                f"{repo_dir}/.venv/bin/pip install pytest -q",
                label="venv-install-pytest",
            )
            print(f"  ✅ Venv created (no requirements.txt found)")
        # Auto-activate the venv in every future bash login/interactive shell
        # so the agent can simply run `python` / `pytest` without absolute paths.
        _exec_check(
            sandbox,
            f"echo 'source {repo_dir}/.venv/bin/activate' >> ~/.bashrc && "
            f"echo 'source {repo_dir}/.venv/bin/activate' >> ~/.profile",
            label="venv-autoactivate",
        )
        print(f"  ✅ Venv auto-activated in ~/.bashrc and ~/.profile")

        # -- Run coding agent --------------------------------------------------
        print(f"\n### Step 8: Run GitHub Copilot agent  [YOLO mode]")
        print(f"  📝 Prompt: {CODING_PROMPT}")
        print()

        # `copilot` binary installed by gh.io/copilot-install — YOLO mode.
        # GH_TOKEN is exported in ~/.bashrc; also pass it explicitly so bash -l
        # picks it up even if profile sourcing is slow.
        # Use -p flag (not positional) as per the official sample.
        # Output is streamed back in real-time via background-process polling.
        agent_cmd = (
            f"cd {repo_dir} && "
            f"GH_TOKEN={PAT} "
            f"bash -lc 'copilot --allow-all-tools -p \"{CODING_PROMPT}\"'"
        )
        exit_code = _exec_stream(sandbox, agent_cmd, poll_interval=3.0, label="copilot-agent")
        if exit_code != 0:
            print(f"  ⚠️  Copilot agent exited with code {exit_code}.")

        # -- Commit and push ---------------------------------------------------
        print(f"\n### Step 9: Commit & push → {GITHUB_BRANCH}")

        # Check if there's anything to commit
        diff_check = sandbox.exec(f"git -C {repo_dir} status --porcelain")
        if not (diff_check.stdout or "").strip():
            print("  ℹ️  No changes detected — nothing to commit.")
        else:
            _exec_check(
                sandbox,
                f"git -C {repo_dir} add -A",
                label="git-add",
            )
            _exec_check(
                sandbox,
                f'git -C {repo_dir} commit -m "chore: yolo-agent changes (run={run_id})"',
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
                f'--title "YOLO agent: run {run_id}" '
                f'--body "Automated changes from yolo-coding agent (run={run_id})\\n\\nPrompt: {CODING_PROMPT[:200]}"'
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
