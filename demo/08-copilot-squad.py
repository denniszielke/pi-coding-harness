"""Run Squad on GitHub Copilot CLI in an ACA Sandbox.

Install Copilot CLI and Squad, clone task-tracker with its existing Squad team,
and implement the late-notification PRD. Run tests, lint, and build before
committing, pushing, and opening a pull request.

GitHub authentication is injected by the sandbox egress proxy for Copilot API
traffic. The PAT is passed only to individual Copilot, git, and gh processes;
it is never written to the sandbox filesystem.

Configuration (.env or environment variables):
  COPILOT_GITHUB_TOKEN      Copilot token (falls back to PAT/GH_TOKEN/GITHUB_TOKEN)
  PAT                       GitHub fine-grained PAT (optional if gh is signed in)
  SQUAD_GITHUB_REPO         target repo (default: denniszielke/task-tracker)
  SQUAD_BASE_BRANCH         branch to clone (default: main)
  SQUAD_BRANCH              branch to push (default: squad-<run_id>)
  SQUAD_PRD                 repo-relative PRD (default: late-notification-prd.md)
  SQUAD_PROMPT              optional additional task instructions
  RESOURCE_GROUP_NAME       resource group (default: aca-sandboxes-rg)
  SANDBOX_GROUP_NAME        sandbox group (default: pi-coding)
  LOCATION                  Azure region (default: westus3)
  EGRESS_EXTRA_HOSTS        additional allowed hosts (space/comma separated)

Usage:
  python demo/08-copilot-squad.py
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml
from azure.containerapps.sandbox import (
    EgressHeader,
    EgressHostRule,
    EgressPolicy,
    EgressRule,
    EgressRuleAction,
    EgressRuleMatch,
    SandboxGroupClient,
    SandboxGroupManagementClient,
    endpoint_for_region,
)
from azure.identity import AzureCliCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = Path(__file__).with_name("06-copilot-cli-policy.yaml")
load_dotenv(ROOT / ".env", override=True)


def _resolve_pat() -> str:
    for variable in ("COPILOT_GITHUB_TOKEN", "PAT", "GH_TOKEN", "GITHUB_TOKEN"):
        token = os.getenv(variable, "").strip()
        if token:
            return token

    if shutil.which("gh"):
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            check=False,
        )
        token = result.stdout.strip()
        if result.returncode == 0 and token:
            return token

    sys.exit(
        "❌ No GitHub token found. Run `gh auth login`, set PAT in .env, "
        "or export GH_TOKEN."
    )


def _require_repo(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        sys.exit("❌ SQUAD_GITHUB_REPO must use the form 'owner/repo'.")
    return value


def _require_branch(name: str, variable: str) -> str:
    invalid = (
        not name
        or name.startswith(("-", ".", "/"))
        or name.endswith((".", "/", ".lock"))
        or ".." in name
        or "@{" in name
        or re.search(r"[\x00-\x20~^:?*\\\[]", name)
    )
    if invalid:
        sys.exit(f"❌ {variable} is not a valid Git branch name.")
    return name


def _require_prd(value: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        sys.exit("❌ SQUAD_PRD must be a non-empty repo-relative path without '..'.")
    return value


PAT = _resolve_pat()
GITHUB_REPO = _require_repo(
    os.getenv("SQUAD_GITHUB_REPO", "denniszielke/task-tracker").strip()
)
run_id = uuid.uuid4().hex[:8]
GITHUB_BASE_BRANCH = _require_branch(
    os.getenv("SQUAD_BASE_BRANCH", "main").strip(),
    "SQUAD_BASE_BRANCH",
)
GITHUB_BRANCH = _require_branch(
    os.getenv("SQUAD_BRANCH", "").strip() or f"squad-{run_id}",
    "SQUAD_BRANCH",
)
SQUAD_VERSION = "0.13.1"
SQUAD_PRD = _require_prd(
    os.getenv("SQUAD_PRD", "late-notification-prd.md").strip()
)
CODING_PROMPT = (
    f"Squad, implement the requirements in the repository PRD {SQUAD_PRD!r}. "
    "First read that PRD in full, late-filter-prd.md, the repository instructions, "
    "and the existing .squad/team.md, routing, and decisions. Use the existing "
    "Squad team and delegate planning, implementation, testing, and review to "
    "the appropriate specialists. Do not reinitialize or replace the team. "
    "Implement and test the late-notification behavior end to end while "
    "preserving the Late Delivery Filter and existing offline behavior. "
    "Work autonomously; record decisions for open questions and explicitly "
    "report any unmet production requirements rather than claiming demo "
    "behavior satisfies them. Use deterministic tests for timing, ordering, "
    "idempotency, dependency traversal, and shop isolation as required by the PRD. "
    "Run npm test, npm run lint, and npm run build and fix failures caused by "
    "your changes. Keep package-lock.json in sync with dependency changes. "
    "Keep all work on the current branch; do not commit, push, open a pull "
    "request, or deploy anything: the harness handles publishing. Finish with "
    "a summary of changes, validation results, and any remaining PRD gaps."
)
extra_prompt = os.getenv("SQUAD_PROMPT", "").strip()
if extra_prompt:
    CODING_PROMPT += f"\n\nAdditional instructions:\n{extra_prompt}"

RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
SANDBOX_GROUP_NAME = os.getenv("SANDBOX_GROUP_NAME", "pi-coding")
LOCATION = os.getenv("LOCATION", "westus3")
_extra_hosts = os.getenv("EGRESS_EXTRA_HOSTS", "")
EGRESS_EXTRA_HOSTS = tuple(
    host.strip()
    for host in _extra_hosts.replace(",", " ").split()
    if host.strip()
)

labels = {"scenario": "copilot-squad", "run": run_id}
git_auth = base64.b64encode(f"x-access-token:{PAT}".encode()).decode()


def _exec_check(sandbox, command: str, *, label: str) -> str:
    result = sandbox.exec(command)
    if result.exit_code != 0:
        raise RuntimeError(
            f"sandbox exec failed [{label}]: exit={result.exit_code}\n"
            f"  out: {(result.stdout or '')[:400]}\n"
            f"  err: {(result.stderr or '')[:400]}"
        )
    return (result.stdout or "").strip()


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


def _exec_stream(
    sandbox,
    command: str,
    *,
    environment: dict[str, str] | None = None,
    poll_interval: float = 3.0,
) -> int:
    tag = uuid.uuid4().hex[:8]
    script_path = f"/tmp/stream_{tag}.sh"
    log_path = f"/tmp/stream_{tag}.log"
    done_path = f"/tmp/stream_{tag}.done"

    sandbox.write_file(script_path, f"#!/bin/bash\n{command}\n")
    _exec_check(sandbox, f"chmod +x {script_path}", label="stream-script")
    environment = environment or {}
    env_prefix = " ".join(
        f"{name}={shlex.quote(value)}" for name, value in environment.items()
    )
    inner_command = (
        f"{env_prefix} bash {script_path}; "
        f"echo $? >{done_path}"
    )
    # Redirect the wrapper too, so it cannot hold the exec response pipes open.
    _exec_check(
        sandbox,
        f"nohup bash -c {shlex.quote(inner_command)} "
        f"</dev/null >{log_path} 2>&1 &",
        label="stream-start",
    )

    lines_shown = 0
    while True:
        time.sleep(poll_interval)
        output = sandbox.exec(
            f"awk 'NR>{lines_shown}' {log_path} 2>/dev/null || true"
        )
        if output.stdout:
            print(output.stdout, end="", flush=True)
            lines_shown += output.stdout.count("\n")

        completed = sandbox.exec(f"cat {done_path} 2>/dev/null || true")
        exit_code = (completed.stdout or "").strip()
        if exit_code and exit_code.lstrip("-").isdigit():
            final_output = sandbox.exec(
                f"awk 'NR>{lines_shown}' {log_path} 2>/dev/null || true"
            )
            if final_output.stdout:
                print(final_output.stdout, end="", flush=True)
            return int(exit_code)


def _portal_url(subscription_id: str, sandbox_id: str) -> str:
    return (
        "https://sandboxes.azure.com/sandbox-groups/"
        f"{subscription_id}/{RESOURCE_GROUP_NAME}/{SANDBOX_GROUP_NAME}/"
        f"sandboxes/{sandbox_id}"
    )


def _project_install_command(repo_dir: str) -> str:
    normalize_lock = """\
import json
from pathlib import Path

path = Path("package-lock.json")
lock = json.loads(path.read_text())
mirror = (
    "https://ms-feed-25.pkgs.visualstudio.com/"
    "1es-public/_packaging/npm-public/npm/registry/"
)
public = "https://registry.npmjs.org/"
changed = 0
for package in lock["packages"].values():
    resolved = package.get("resolved", "")
    if resolved.startswith(mirror):
        package["resolved"] = public + resolved[len(mirror):]
        changed += 1
if changed:
    path.write_text(json.dumps(lock, indent=2) + "\\n")
print(f"Normalized {changed} npm tarball URLs to the public registry.")
"""
    return (
        f"cd {shlex.quote(repo_dir)} && "
        f"python3 -c {shlex.quote(normalize_lock)} && "
        "npm ci --registry=https://registry.npmjs.org/ --no-audit --no-fund"
    )


def _load_policy() -> EgressPolicy:
    raw = yaml.safe_load(POLICY_FILE.read_text())
    host_rules = [
        EgressHostRule(pattern=item["pattern"], action=item["action"])
        for item in raw.get("hostRules", [])
    ]
    host_rules.append(EgressHostRule(pattern="registry.npmjs.org", action="Allow"))
    host_rules.extend(
        EgressHostRule(pattern=host, action="Allow")
        for host in EGRESS_EXTRA_HOSTS
    )

    transform_rules = []
    placeholder_count = 0
    for item in raw.get("rules", []):
        match = item["match"]
        action = item["action"]
        headers = []
        for header in action.get("headers", []):
            value = header.get("value")
            if value and "PASTE_PAT_HERE" in value:
                placeholder_count += value.count("PASTE_PAT_HERE")
                value = value.replace("PASTE_PAT_HERE", PAT)
            headers.append(
                EgressHeader(
                    operation=header["operation"],
                    name=header["name"],
                    value=value,
                )
            )
        transform_rules.append(
            EgressRule(
                name=item.get("name"),
                match=EgressRuleMatch(
                    host=match["host"],
                    path=match.get("path"),
                    methods=match.get("methods"),
                ),
                action=EgressRuleAction(type=action["type"], headers=headers),
            )
        )

    if placeholder_count != 3:
        raise ValueError(
            f"expected exactly 3 PAT placeholders in {POLICY_FILE.name}; "
            f"found {placeholder_count}"
        )
    if any("githubcopilot.com" in rule.pattern for rule in host_rules):
        raise ValueError(
            "hostRules must not match githubcopilot.com; that would bypass "
            "the PAT-injection transform rules"
        )

    return EgressPolicy(
        default_action=raw["defaultAction"],
        host_rules=host_rules,
        rules=transform_rules,
        traffic_inspection=raw["trafficInspection"],
    )


def main() -> int:
    account = subprocess.run(
        ["az", "account", "show", "--output", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    subscription = json.loads(account.stdout)
    subscription_id = (
        os.getenv("AZURE_SUBSCRIPTION_ID", "").strip() or subscription["id"]
    )

    print(f"🧪 Scenario:              copilot-squad (run={run_id})")
    print(f"🔑 Subscription:          {subscription_id}")
    print(f"🌍 Region:                {LOCATION}")
    print(f"📁 Resource group:        {RESOURCE_GROUP_NAME}")
    print(f"📦 Sandbox group:         {SANDBOX_GROUP_NAME}")
    print(f"🐙 Target repo:           {GITHUB_REPO}")
    print(f"🌿 Base / push branch:    {GITHUB_BASE_BRANCH} → {GITHUB_BRANCH}")
    print(f"📋 PRD:                   {SQUAD_PRD}")
    prompt_preview = CODING_PROMPT[:80] + ("…" if len(CODING_PROMPT) > 80 else "")
    print(f"📝 Prompt:                {prompt_preview}")

    credential = AzureCliCredential()
    resource_client = ResourceManagementClient(credential, subscription_id)
    group_client = SandboxGroupManagementClient(
        credential,
        subscription_id=subscription_id,
        resource_group=RESOURCE_GROUP_NAME,
    )

    print("\n### Step 1: Resource group + sandbox group")
    if resource_client.resource_groups.check_existence(RESOURCE_GROUP_NAME):
        resource_group = resource_client.resource_groups.get(RESOURCE_GROUP_NAME)
        print(f"♻️  Using existing RG: {resource_group.name} ({resource_group.location})")
    else:
        resource_group = resource_client.resource_groups.create_or_update(
            RESOURCE_GROUP_NAME, {"location": LOCATION, "tags": labels}
        )
        print(f"✅ Created RG: {resource_group.name} ({resource_group.location})")

    existing = next(
        (group for group in group_client.list_groups() if group.name == SANDBOX_GROUP_NAME),
        None,
    )
    if existing:
        print(f"♻️  Using existing sandbox group: {SANDBOX_GROUP_NAME}")
    else:
        group_client.create_group(
            SANDBOX_GROUP_NAME, location=resource_group.location, tags=labels
        )
        print(f"✅ Created sandbox group: {SANDBOX_GROUP_NAME}")
    sandbox_group = group_client.get_group(SANDBOX_GROUP_NAME)

    print("\n### Step 2: Data-plane access")
    authorization_client = AuthorizationManagementClient(credential, subscription_id)
    scope = f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP_NAME}"
    role_name = "Container Apps SandboxGroup Data Owner"
    role_definition = next(
        authorization_client.role_definitions.list(
            scope, filter=f"roleName eq '{role_name}'"
        )
    )
    signed_in_user = subprocess.run(
        ["az", "ad", "signed-in-user", "show", "--query", "id", "--output", "tsv"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    try:
        authorization_client.role_assignments.create(
            scope,
            str(uuid.uuid4()),
            {
                "role_definition_id": role_definition.id,
                "principal_id": signed_in_user,
                "principal_type": "User",
            },
        )
        print(f"✅ Assigned '{role_name}'. Waiting 60s for propagation...")
        time.sleep(60)
    except Exception as error:
        if "RoleAssignmentExists" in str(error) or "Conflict" in str(error):
            print(f"♻️  '{role_name}' already assigned.")
        else:
            raise

    client = SandboxGroupClient(
        endpoint_for_region(sandbox_group.location),
        credential,
        subscription_id=subscription_id,
        resource_group=RESOURCE_GROUP_NAME,
        sandbox_group=SANDBOX_GROUP_NAME,
    )

    sandbox = None
    try:
        print("\n### Step 3: Boot sandbox (ubuntu, 2 CPU, 4 GB)")
        sandbox = client.begin_create_sandbox(
            disk="ubuntu", cpu="2000m", memory="4096Mi", labels=labels
        ).result()
        print(f"✅ Sandbox ready: {sandbox.sandbox_id}")
        print(f"   Portal: {_portal_url(subscription_id, sandbox.sandbox_id)}")
        _wait_exec_up(sandbox)

        print("\n### Step 4: Install toolchain [egress: default ALLOW]")
        _exec_check(
            sandbox,
            "apt-get update -qq && apt-get install -y -qq "
            "git gh curl ca-certificates python3-pip python3-venv poppler-utils",
            label="toolchain-install",
        )
        _exec_check(
            sandbox,
            "python3 -m ensurepip --version && python3 -m pip --version && "
            "pdftotext -v",
            label="python-pdf-toolchain-check",
        )
        _exec_check(
            sandbox,
            "timeout 180s bash -lc 'curl -fsSL https://gh.io/copilot-install | bash'",
            label="copilot-install",
        )
        version = _exec_check(sandbox, "copilot --version", label="copilot-version")
        print(f"✅ GitHub Copilot CLI installed: {version}")
        _exec_check(
            sandbox,
            "timeout 180s bash -o pipefail -c "
            "'curl -fsSL https://deb.nodesource.com/setup_22.x | bash -' && "
            "apt-get install -y -qq nodejs",
            label="node-install",
        )
        install_exit = _exec_stream(
            sandbox,
            f"npm install --global --engine-strict "
            f"--registry=https://registry.npmjs.org/ "
            f"@bradygaster/squad-cli@{SQUAD_VERSION}",
        )
        if install_exit != 0:
            raise RuntimeError(f"Squad installation exited with code {install_exit}")
        squad_version = _exec_check(
            sandbox,
            "node --version && npm --version && squad --version",
            label="squad-version",
        )
        print(f"✅ Node.js / npm / Squad installed:\n{squad_version}")

        print("\n### Step 5: Apply deny-default egress policy")
        policy = _load_policy()
        applied = sandbox.set_egress_policy(policy)
        if applied.traffic_inspection != "Full":
            raise RuntimeError("egress policy did not enable full traffic inspection")
        print(
            f"✅ Policy applied: {len(applied.host_rules)} host rules, "
            f"{len(applied.rules)} PAT-injection transforms"
        )

        print("\n### Step 6: Verify proxy-injected GitHub authentication")
        login = _exec_check(
            sandbox,
            "curl -fsSL https://api.github.com/user | python3 -c "
            "'import json,sys; print(json.load(sys.stdin)[\"login\"])'",
            label="github-auth",
        )
        print(f"✅ Authenticated as GitHub user: {login}")

        repo_name = GITHUB_REPO.rsplit("/", 1)[1]
        repo_dir = f"/root/{repo_name}"
        git_header = f"AUTHORIZATION: basic {git_auth}"

        print(f"\n### Step 7: Clone {GITHUB_REPO}")
        _exec_check(
            sandbox,
            f"git -c http.https://github.com/.extraheader='{git_header}' "
            f"clone --branch '{GITHUB_BASE_BRANCH}' --depth 50 "
            f"https://github.com/{GITHUB_REPO}.git {repo_dir}",
            label="git-clone",
        )
        _exec_check(
            sandbox,
            f"git -C {repo_dir} checkout -b '{GITHUB_BRANCH}'",
            label="git-checkout",
        )
        _exec_check(
            sandbox,
            'git config --global user.email "copilot-agent@sandbox.local" && '
            'git config --global user.name "Copilot CLI Agent"',
            label="git-identity",
        )
        print(f"✅ Created branch: {GITHUB_BRANCH}")

        print("\n### Step 8: Verify existing Squad team and install project dependencies")
        _exec_check(
            sandbox,
            f"cd {shlex.quote(repo_dir)} && "
            "test -s .github/agents/squad.agent.md && "
            "test -s .squad/team.md && "
            f"test -s {shlex.quote(SQUAD_PRD)} && "
            "test -s package.json && test -s package-lock.json",
            label="squad-project-check",
        )
        install_exit = _exec_stream(
            sandbox,
            _project_install_command(repo_dir),
        )
        if install_exit != 0:
            raise RuntimeError(
                f"Project dependency installation exited with code {install_exit}"
            )

        print("\n### Step 9: Run Squad coordinator on the PRD [YOLO mode]")
        trust_config = """\
import json
import sys
from pathlib import Path

path = Path.home() / ".copilot" / "config.json"
config = json.loads(path.read_text()) if path.exists() else {}
key = "trustedFolders" if "trustedFolders" in config else "trusted_folders"
folders = config.setdefault(key, [])
repo = str(Path(sys.argv[1]).resolve())
if repo not in folders:
    folders.append(repo)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(config, indent=2) + "\\n")
"""
        _exec_check(
            sandbox,
            f"python3 -c {shlex.quote(trust_config)} {shlex.quote(repo_dir)}",
            label="copilot-folder-trust",
        )
        sandbox.write_file("/tmp/coding-prompt.txt", CODING_PROMPT)
        exit_code = _exec_stream(
            sandbox,
            f"cd {shlex.quote(repo_dir)} && "
            "copilot --agent=squad --yolo "
            '--prompt="$(cat /tmp/coding-prompt.txt)"',
            environment={
                "COPILOT_GITHUB_TOKEN": PAT,
                "GITHUB_TOKEN": PAT,
                "GH_TOKEN": PAT,
                "npm_config_registry": "https://registry.npmjs.org/",
            },
        )
        if exit_code != 0:
            raise RuntimeError(f"Squad coordinator exited with code {exit_code}")

        print("\n### Step 10: Validate implementation before publishing")
        validation_exit = _exec_stream(
            sandbox,
            _project_install_command(repo_dir) + " && "
            "npm test && npm run lint && npm run build",
        )
        if validation_exit != 0:
            raise RuntimeError(
                f"Project validation exited with code {validation_exit}; "
                "changes will not be pushed"
            )

        print(f"\n### Step 11: Commit and push → {GITHUB_BRANCH}")
        status = _exec_check(
            sandbox,
            f"git -C {repo_dir} status --porcelain",
            label="git-status",
        )
        if not status:
            print("ℹ️  Squad made no changes; nothing to commit or push.")
        else:
            _exec_check(
                sandbox,
                f"git -C {repo_dir} add -A && "
                f"git -C {repo_dir} commit -m "
                f"'feat: Squad PRD implementation (run={run_id})'",
                label="git-commit",
            )
            _exec_check(
                sandbox,
                f"git -c http.https://github.com/.extraheader='{git_header}' "
                f"-C {repo_dir} push origin HEAD:refs/heads/'{GITHUB_BRANCH}'",
                label="git-push",
            )
            print(f"✅ Pushed branch: {GITHUB_BRANCH}")

            pr_body = (
                f"Implements {SQUAD_PRD} using the existing Squad team on Copilot "
                "CLI. Validated with npm test, npm run lint, and npm run build. "
                f"Run: {run_id}."
            )
            pr = sandbox.exec(
                f"GH_TOKEN='{PAT}' gh pr create "
                f"--repo '{GITHUB_REPO}' "
                f"--head '{GITHUB_BRANCH}' "
                f"--base '{GITHUB_BASE_BRANCH}' "
                f"--title 'Squad: PRD implementation (run={run_id})' "
                f"--body {shlex.quote(pr_body)}"
            )
            if pr.exit_code == 0:
                print(f"🎉 Pull request created: {(pr.stdout or '').strip()}")
            else:
                raise RuntimeError(
                    "branch pushed, but pull request creation failed: "
                    f"{(pr.stderr or pr.stdout or '')[:400]}"
                )

        print(f"\n✅ Done! Branch '{GITHUB_BRANCH}' in {GITHUB_REPO}")
    finally:
        if sandbox is not None:
            print(f"\n### Cleanup: deleting sandbox {sandbox.sandbox_id}...")
            try:
                sandbox.delete()
                print("🗑️  Sandbox deleted.")
            except Exception as error:
                print(f"⚠️  Delete warning: {error}")
        else:
            for leaked in client.list_sandboxes(labels={"run": run_id}):
                client.delete_sandbox(leaked.id)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(f"❌ Command failed: {' '.join(error.cmd)}\n{error.stderr or ''}")
