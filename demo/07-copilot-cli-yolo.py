"""Run GitHub Copilot CLI as an autonomous coding agent in an ACA Sandbox.

The script creates an ephemeral Ubuntu sandbox, installs GitHub Copilot CLI,
clones a configured repository, runs Copilot with all tools allowed, then
commits, pushes, and opens a pull request when changes were made.

GitHub authentication is injected by the sandbox egress proxy for Copilot API
traffic. The PAT is passed only to individual Copilot, git, and gh processes;
it is never written to the sandbox filesystem.

Configuration (.env or environment variables):
  COPILOT_GITHUB_TOKEN      Copilot token (falls back to PAT/GH_TOKEN/GITHUB_TOKEN)
  PAT                       GitHub fine-grained PAT (optional if gh is signed in)
  GITHUB_REPO               target repository as "owner/repo" (required)
  GITHUB_BASE_BRANCH        branch to clone (default: main)
  GITHUB_BRANCH             branch to push (default: copilot-<run_id>)
  CODING_PROMPT             natural-language coding task
  RESOURCE_GROUP_NAME       resource group (default: aca-sandboxes-rg)
  SANDBOX_GROUP_NAME        sandbox group (default: pi-coding)
  LOCATION                  Azure region (default: westus3)
  EGRESS_EXTRA_HOSTS        additional allowed hosts (space/comma separated)

Usage:
  python demo/07-copilot-cli-yolo.py
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
        sys.exit("❌ GITHUB_REPO must use the form 'owner/repo'.")
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


PAT = _resolve_pat()
GITHUB_REPO = _require_repo(os.getenv("GITHUB_REPO", "").strip())
run_id = uuid.uuid4().hex[:8]
GITHUB_BASE_BRANCH = _require_branch(
    os.getenv("GITHUB_BASE_BRANCH", "main").strip(),
    "GITHUB_BASE_BRANCH",
)
GITHUB_BRANCH = _require_branch(
    os.getenv("GITHUB_BRANCH", "").strip() or f"copilot-{run_id}",
    "GITHUB_BRANCH",
)
CODING_PROMPT = os.getenv(
    "CODING_PROMPT",
    "Review the codebase, fix any obvious bugs, run the relevant tests, and "
    "summarize the changes you made.",
).strip()
if not CODING_PROMPT:
    sys.exit("❌ CODING_PROMPT must not be empty.")

RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
SANDBOX_GROUP_NAME = os.getenv("SANDBOX_GROUP_NAME", "pi-coding")
LOCATION = os.getenv("LOCATION", "westus3")
_extra_hosts = os.getenv("EGRESS_EXTRA_HOSTS", "")
EGRESS_EXTRA_HOSTS = tuple(
    host.strip()
    for host in _extra_hosts.replace(",", " ").split()
    if host.strip()
)

labels = {"scenario": "copilot-cli-yolo", "run": run_id}
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
        f"{env_prefix} bash {script_path} >{log_path} 2>&1; "
        f"echo $? >{done_path}"
    )
    sandbox.exec(f"bash -c {shlex.quote(inner_command)} &")

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


def _load_policy() -> EgressPolicy:
    raw = yaml.safe_load(POLICY_FILE.read_text())
    host_rules = [
        EgressHostRule(pattern=item["pattern"], action=item["action"])
        for item in raw.get("hostRules", [])
    ]
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

    print(f"🧪 Scenario:              copilot-cli-yolo (run={run_id})")
    print(f"🔑 Subscription:          {subscription_id}")
    print(f"🌍 Region:                {LOCATION}")
    print(f"📁 Resource group:        {RESOURCE_GROUP_NAME}")
    print(f"📦 Sandbox group:         {SANDBOX_GROUP_NAME}")
    print(f"🐙 Target repo:           {GITHUB_REPO}")
    print(f"🌿 Base / push branch:    {GITHUB_BASE_BRANCH} → {GITHUB_BRANCH}")
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
            "apt-get update -qq && apt-get install -y -qq git gh",
            label="toolchain-install",
        )
        _exec_check(
            sandbox,
            "timeout 180s bash -lc 'curl -fsSL https://gh.io/copilot-install | bash'",
            label="copilot-install",
        )
        version = _exec_check(sandbox, "copilot --version", label="copilot-version")
        print(f"✅ GitHub Copilot CLI installed: {version}")

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

        print("\n### Step 8: Run GitHub Copilot CLI [YOLO mode]")
        sandbox.write_file("/tmp/coding-prompt.txt", CODING_PROMPT)
        exit_code = _exec_stream(
            sandbox,
            f"cd {repo_dir} && "
            'copilot --allow-all-tools -p "$(cat /tmp/coding-prompt.txt)"',
            environment={
                "COPILOT_GITHUB_TOKEN": PAT,
                "GITHUB_TOKEN": PAT,
                "GH_TOKEN": PAT,
            },
        )
        if exit_code != 0:
            raise RuntimeError(f"Copilot CLI exited with code {exit_code}")

        print(f"\n### Step 9: Commit and push → {GITHUB_BRANCH}")
        status = _exec_check(
            sandbox,
            f"git -C {repo_dir} status --porcelain",
            label="git-status",
        )
        if not status:
            print("ℹ️  Copilot made no changes; nothing to commit or push.")
        else:
            _exec_check(
                sandbox,
                f"git -C {repo_dir} add -A && "
                f"git -C {repo_dir} commit -m "
                f"'chore: Copilot CLI changes (run={run_id})'",
                label="git-commit",
            )
            _exec_check(
                sandbox,
                f"git -c http.https://github.com/.extraheader='{git_header}' "
                f"-C {repo_dir} push origin HEAD:refs/heads/'{GITHUB_BRANCH}'",
                label="git-push",
            )
            print(f"✅ Pushed branch: {GITHUB_BRANCH}")

            pr = sandbox.exec(
                f"GH_TOKEN='{PAT}' gh pr create "
                f"--repo '{GITHUB_REPO}' "
                f"--head '{GITHUB_BRANCH}' "
                f"--base '{GITHUB_BASE_BRANCH}' "
                f"--title 'Copilot CLI: run {run_id}' "
                f"--body 'Automated changes from Copilot CLI YOLO run {run_id}.'"
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
