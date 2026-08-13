"""Run GitHub Copilot CLI interactively in an ACA Sandbox.

This adapts the Azure Samples gh-copilot-cli scenario to the environment used
by this repository. The GitHub PAT is read from the root .env and inserted into
the egress policy only in memory. Requests receive the Authorization header at
the sandbox proxy, so the PAT is not written into the sandbox filesystem.

Configuration (.env or environment variables):
  PAT                       GitHub fine-grained PAT (required)
  AZURE_SUBSCRIPTION_ID     subscription (default: active Azure CLI account)
  RESOURCE_GROUP_NAME       resource group (default: aca-sandboxes-rg)
  SANDBOX_GROUP_NAME        sandbox group (default: pi-coding)
  LOCATION                  Azure region (default: westus3)
  EGRESS_EXTRA_HOSTS        additional allowed hosts (space/comma separated)

Usage:
  python demo/06-copilot-cli.py
"""

from __future__ import annotations

import json
import os
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

PAT = os.getenv("PAT", "").strip()
if not PAT:
    sys.exit("❌ PAT is not set. Add it to .env or export it as an env var.")

RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
SANDBOX_GROUP_NAME = os.getenv("SANDBOX_GROUP_NAME", "pi-coding")
LOCATION = os.getenv("LOCATION", "westus3")
_extra_hosts = os.getenv("EGRESS_EXTRA_HOSTS", "")
EGRESS_EXTRA_HOSTS = tuple(
    host.strip()
    for host in _extra_hosts.replace(",", " ").split()
    if host.strip()
)

run_id = uuid.uuid4().hex[:8]
labels = {"scenario": "copilot-cli", "run": run_id}


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
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "").strip() or subscription["id"]

    print(f"🧪 Scenario:              copilot-cli (run={run_id})")
    print(f"🔑 Subscription:          {subscription_id}")
    print(f"🌍 Region:                {LOCATION}")
    print(f"📁 Resource group:        {RESOURCE_GROUP_NAME}")
    print(f"📦 Sandbox group:         {SANDBOX_GROUP_NAME}")

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

        print("\n### Step 4: Install GitHub Copilot CLI [egress: default ALLOW]")
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

        print("\n### Step 7: Open interactive sandbox shell")
        print("Run `copilot` in the shell. Type `exit` when finished.")
        if shutil.which("aca"):
            subprocess.run(["aca", "sandbox", "shell", "--id", sandbox.sandbox_id], check=False)
        else:
            print("The `aca` CLI is not installed locally; use the portal bash tab:")
            print(f"  {_portal_url(subscription_id, sandbox.sandbox_id)}")
            input("Press Enter when you are finished with the sandbox... ")
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