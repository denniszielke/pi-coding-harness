"""
Azure Container Apps Sandboxes - Getting Started

Converted from: https://github.com/Azure-Samples/azure-container-apps-sandboxes/blob/main/python/labs/01-getting-started.ipynb

Full lifecycle walkthrough: create sandbox group → create sandbox → exec commands →
read/write files → expose port → inspect stats → snapshot & restore → disk images →
volumes → stop/resume → lifecycle policies → egress → secrets → clean up.
"""

import json
import os
import subprocess
import sys
import time
import uuid
import urllib.request
from pathlib import Path

from dotenv import load_dotenv
from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.containerapps.sandbox import (
    SandboxGroupManagementClient,
    SandboxGroupClient,
    endpoint_for_region,
    AddVolumeMountRequest,
    LifecyclePolicy,
    AutoDeletePolicy,
    AutoSuspendPolicy,
)

# ── Load configuration from .env ─────────────────────────────────────────────
load_dotenv()

resource_group_name = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
sandbox_group_name = os.getenv("SANDBOX_GROUP_NAME", "lab-01-getting-started")
location = os.getenv("LOCATION", "westus3")
lab_name = Path(__file__).stem
lab_labels = {"lab": lab_name}

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
resource_mgmt_client = ResourceManagementClient(cli_credential, subscription_id)
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


# ── Step 1: Create the resource group and sandbox group ──────────────────────
print("\n### Step 1: Create resource group and sandbox group")

if resource_mgmt_client.resource_groups.check_existence(resource_group_name):
    resource_group = resource_mgmt_client.resource_groups.get(resource_group_name)
    print(f'♻️ Using existing resource group: {resource_group.name} ({resource_group.location})')
else:
    resource_group = resource_mgmt_client.resource_groups.create_or_update(
        resource_group_name, {"location": location, "tags": lab_labels})
    print(f'✅ Created resource group: {resource_group.name} ({resource_group.location})')

existing = next((g for g in sandboxgroup_mgmt_client.list_groups() if g.name == sandbox_group_name), None)
if existing:
    action, icon = "Using existing", "♻️"
else:
    sandboxgroup_mgmt_client.create_group(
        sandbox_group_name, location=resource_group.location, tags=lab_labels)
    action, icon = "Created", "✅"

sandboxgroup = sandboxgroup_mgmt_client.get_group(sandbox_group_name)
sandbox_group_url = (
    f"https://sandboxes.azure.com/sandbox-groups/{subscription_id}/"
    f"{resource_group_name}/{sandbox_group_name}/sandboxes"
)
print(f'{icon} {action} sandbox group: {sandboxgroup.name}')
print(f'  🆔 Id:                 {sandboxgroup.id}')
print(f'  🌍 Location:           {sandboxgroup.location}')
print(f'  ⚙️ Provisioning state: {sandboxgroup.properties["provisioningState"]}')
print(f'  🏷️ Tags:               {sandboxgroup.tags or "{}"}')
print(f'  🔗 Portal:             {sandbox_group_url}')


# ── Step 2: Grant yourself data-plane access ─────────────────────────────────
print("\n### Step 2: Grant data-plane access")

auth_client = AuthorizationManagementClient(cli_credential, subscription_id)
role_name = "Container Apps SandboxGroup Data Owner"
scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
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
    print(f"✅ Assigned '{role_name}' to you ({subscription['user']['name']})")
    print("  ⏳ Waiting 60s for role assignment to propagate...")
    time.sleep(60)
except Exception as ex:
    if "RoleAssignmentExists" in str(ex) or "Conflict" in str(ex):
        print(f"♻️ '{role_name}' already assigned to you ({subscription['user']['name']})")
    else:
        raise



print(f'  🆔 Role definition:  {role_def.id}')
print(f'  👤 User principalId: {user_principal_id}')
print(f'  🎯 Scope:            {scope}')


# ── Step 3: Create a sandbox from a public disk image ────────────────────────
print("\n### Step 3: Create a sandbox")

client = SandboxGroupClient(
    endpoint_for_region(sandboxgroup.location),
    cli_credential,
    subscription_id=subscription_id,
    resource_group=resource_group_name,
    sandbox_group=sandbox_group_name,
)

public_disk_images = list(client.list_public_disk_images())
print(f'📚 Available public disk images: {", ".join(image.name for image in public_disk_images)}')

sandbox = client.begin_create_sandbox(
    disk="ubuntu", labels={**lab_labels, "env": "development"}
).result()

sandbox_details = sandbox.get()
sandbox_url = (
    f"https://sandboxes.azure.com/sandbox-groups/{subscription_id}/"
    f"{resource_group_name}/{sandbox_group_name}/sandboxes/{sandbox_details.id}"
)
print('\n📦 Details for the sandbox created:')
print(f'  🆔 ID             : {sandbox_details.id}')
print(f'  🟢 State          : {sandbox_details.state}')
print(f'  🌍 Region         : {sandbox_details.region}')
print(f'  🖥️ VMM type       : {sandbox_details.vmm_type}')
print(f'  💿 Disk image     : {sandbox_details.sources_ref.disk_image if sandbox_details.sources_ref else None}')
print(f'  🕒 Created at     : {sandbox_details.created_at}')
print(f'  ⚙️ CPU            : {sandbox_details.resources.cpu if sandbox_details.resources else None}')
print(f'  🧠 Memory         : {sandbox_details.resources.memory if sandbox_details.resources else None}')
print(f'  🏷️ Labels         : {sandbox_details.labels or "{}"}')
print(f'  🔗 Portal         : {sandbox_url}')


# ── Step 4: Execute commands ─────────────────────────────────────────────────
print("\n### Step 4: Execute commands")

result = sandbox.exec("whoami && uname -a")
print(f'🔢 exit code: {result.exit_code}')
if result.stdout:
    print(f'📤 stdout: {result.stdout}')
if result.stderr:
    print(f'⚠️ stderr: {result.stderr}')


# ── Step 5: Write and read files ─────────────────────────────────────────────
print("\n### Step 5: Write and read files")

file_path = "index.html"
file_content = "<html><body><h1>Hello from Azure Container Apps sandboxes!</h1></body></html>"

sandbox.write_file(file_path, file_content)
print(f'📝 Wrote {len(file_content)} bytes to {file_path}')

stat = sandbox.stat_file(file_path)
print(f'📊 stat: size={stat.size} bytes, is_directory={stat.is_directory}')

content = sandbox.read_file(file_path)
print(f'📖 Read from {file_path}: {content.decode()}')
assert file_content in content.decode()


# ── Step 6: Expose a port with a public URL ──────────────────────────────────
print("\n### Step 6: Expose a port")

port_number = 8080
result = sandbox.exec(f"nohup python3 -m http.server {port_number} >/tmp/http.log 2>&1 &")
print(f'🔢 exit code: {result.exit_code}')

port = sandbox.add_port(port_number, anonymous=True)
print(f'🌐 Public URL: {port.url}')

last_err = None
for attempt in range(10):
    try:
        with urllib.request.urlopen(port.url, timeout=5) as resp:
            body = resp.read().decode()
        print(f'✅ HTTP {resp.status} (after {attempt + 1} attempt[s]) — content from the web: {body}')
        assert file_content in body
        break
    except Exception as ex:
        last_err = ex
        time.sleep(1)
else:
    print(f'⚠️ Could not reach {port.url}: {last_err}')
    print('   Check the in-sandbox server log: sandbox.exec("cat /tmp/http.log")')


# ── Step 7: Inspect runtime stats ────────────────────────────────────────────
print("\n### Step 7: Inspect runtime stats")

stats = sandbox.get_stats()

cpu = stats.cpu
cores = (cpu.usage_nano_cores or 0) / 1_000_000_000 if cpu else 0
print(f'⚙️ CPU:     {cores:.3f} cores ({cores * 1000:.0f} mCPU)')

mem = stats.memory
used_mb = (mem.used_bytes or 0) // 1024 // 1024 if mem else 0
total_mb = (mem.total_bytes or 0) // 1024 // 1024 if mem else 0
mem_pct = (used_mb / total_mb * 100) if total_mb else 0
print(f'🧠 Memory:  {used_mb}MB / {total_mb}MB ({mem_pct:.1f}%)')

storage = stats.storage
if storage:
    used_gb = (storage.used_bytes or 0) / 1024 / 1024 / 1024
    total_gb = (storage.total_bytes or 0) / 1024 / 1024 / 1024
    storage_pct = (used_gb / total_gb * 100) if total_gb else 0
    print(f'💿 Storage: {used_gb:.2f}GB / {total_gb:.2f}GB ({storage_pct:.1f}%)')
else:
    print('💿 Storage: (no data)')

net = stats.network
rx_mb = (net.rx_bytes or 0) / 1024 / 1024 if net else 0
tx_mb = (net.tx_bytes or 0) / 1024 / 1024 if net else 0
print(f'🌐 Network: rx {rx_mb:.2f}MB / tx {tx_mb:.2f}MB')


# ── Step 8: Snapshots ────────────────────────────────────────────────────────
print("\n### Step 8: Snapshots — capture and restore")

snapshot = sandbox.create_snapshot(name="getting-started", labels=lab_labels)
print(f'📸 Snapshot created: {snapshot.id}')
print(f'  🕒 Created at: {snapshot.created_at_utc}')

snapshots = list(client.list_snapshots())
print(f'\n📚 Total snapshots in group: {len(snapshots)}')
for s in snapshots:
    print(f'  - {s.id} (sandbox={s.sandbox_id})')

restored = client.begin_create_sandbox(snapshot_id=snapshot.id).result()
print(f'\n♻️ Restored sandbox from snapshot: {restored.sandbox_id}')

restored.wait_for_running(timeout=120)
verify = restored.exec("echo restored")
print(f'✅ Verified restored sandbox: {(verify.stdout or "").strip()}')

client.delete_sandbox(restored.sandbox_id)
client.delete_snapshot(snapshot.id)
print(f'🗑️ Deleted restored sandbox and snapshot {snapshot.id}')


# ── Step 9: Disk images ──────────────────────────────────────────────────────
print("\n### Step 9: Disk images — bring your own root filesystem")

disk_image_from_snapshot = sandbox.commit(name="my-custom-image")
print(f'💾 Committed sandbox to disk image: {disk_image_from_snapshot.id}')

sandbox_from_committed_disk_image = client.begin_create_sandbox(
    disk_id=disk_image_from_snapshot.id, labels=lab_labels
).result()
print(f'🚀 Created sandbox from committed disk: {sandbox_from_committed_disk_image.sandbox_id}')

disk_image_from_container = client.create_disk_image("docker.io/library/ubuntu:22.04", name="ubuntu-22")
print(f'📦 Created disk image from container: {disk_image_from_container.id}')

sandbox_from_container_image = client.begin_create_sandbox(
    disk_id=disk_image_from_container.id, labels=lab_labels
).result()
print(f'🚀 Created sandbox from container image: {sandbox_from_container_image.sandbox_id}')

private_disk_images = list(client.list_disk_images())
print(f'\n📚 Available private disk images: {", ".join(image.name or image.id for image in private_disk_images)}')

client.delete_sandbox(sandbox_from_committed_disk_image.sandbox_id)
client.delete_sandbox(sandbox_from_container_image.sandbox_id)
print('🗑️ Deleted transient disk-image sandboxes')

client.delete_disk_image(disk_image_from_snapshot.id)
client.delete_disk_image(disk_image_from_container.id)
print('🗑️ Deleted disk images')


# ── Step 10: Volumes ─────────────────────────────────────────────────────────
print("\n### Step 10: Volumes — shared persistent storage")

volume_name = f"vol-{uuid.uuid4().hex[:8]}"
client.create_volume(volume_name, type="AzureBlob")
mount = AddVolumeMountRequest(volume_name=volume_name, mountpoint="/mnt/shared")
print(f'📁 Created volume: {volume_name}')

try:
    producer = client.begin_create_sandbox(labels={**lab_labels, "role": "producer"}).result()
    producer.add_volume_mount(mount)
    producer.exec("echo '{\"answer\":42}' > /mnt/shared/output.json")

    consumer = client.begin_create_sandbox(labels={**lab_labels, "role": "consumer"}).result()
    consumer.add_volume_mount(mount)
    read = consumer.exec("cat /mnt/shared/output.json").stdout.strip()
    print(f'✍️  Producer {producer.sandbox_id} wrote -> 📖 Consumer {consumer.sandbox_id} read: {read}')
    assert "42" in read
finally:
    for sbx in (producer, consumer):
        client.delete_sandbox(sbx.sandbox_id)
    client.delete_volume(volume_name)
    print(f'🗑️ Cleaned up sandboxes and volume {volume_name}')


# ── Step 11: Stop and resume ─────────────────────────────────────────────────
print("\n### Step 11: Stop and resume")

sandbox.stop()
print(f'⏸️ Stopped sandbox: {sandbox.sandbox_id}  new state={client.get_sandbox(sandbox.sandbox_id).state}')

sandbox.resume()
sandbox.wait_for_running(timeout=120)
print(f'▶️ Resumed sandbox: {sandbox.sandbox_id}  new state={client.get_sandbox(sandbox.sandbox_id).state}')

sandbox.ensure_running()
assert "Running" in client.get_sandbox(sandbox.sandbox_id).state
result = sandbox.exec("echo Back from suspend!")
print(f'📤 stdout: {result.stdout.strip()}')


# ── Step 12: Lifecycle policies ──────────────────────────────────────────────
print("\n### Step 12: Configure lifecycle policies")

sandbox.set_lifecycle_policy(LifecyclePolicy(
    auto_suspend=AutoSuspendPolicy(enabled=True, interval=10, mode="Memory"),
    auto_delete=AutoDeletePolicy(enabled=True, delete_interval_seconds=600),
))
print(f'⚙️ Policy applied — state now: {client.get_sandbox(sandbox.sandbox_id).state}')

for _ in range(60):
    state = client.get_sandbox(sandbox.sandbox_id).state
    if state != "Running":
        break
    time.sleep(1)
print(f'💤 Final state after suspend: {state}')
assert "Idle" in state

sandbox.resume()
sandbox.wait_for_running(timeout=120)
print(f'▶️ Resumed - state now: {client.get_sandbox(sandbox.sandbox_id).state}')


# ── Step 13: Egress policies ─────────────────────────────────────────────────
print("\n### Step 13: Egress policies")


def http_status(host):
    r = sandbox.exec(f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 8 https://{host} || echo FAIL")
    return r.stdout.strip() or "FAIL"


sandbox.ensure_running()
print(f'🌐 Baseline example.com -> {http_status("example.com")}')

sandbox.set_egress_default("Deny")
policy = sandbox.add_egress_host_rule("*.github.com", action="Allow")
print(f'🔒 Policy: default={policy.default_action}, rules={[(r.pattern, r.action) for r in policy.host_rules]}')

for attempt in range(15):
    if http_status("example.com") != "200":
        break
    time.sleep(1)
print(f'⏱️ Enforcement active after ~{attempt + 1}s')

example_http_status = http_status("example.com")
assert "403" in example_http_status
print(f'🚫 example.com (denied)    -> {example_http_status}')

github_http_status = http_status("api.github.com")
assert "200" in github_http_status
print(f'✅ api.github.com (allowed) -> {github_http_status}')

for attempt in range(20):
    net_decisions = sandbox.get_egress_decisions().network_egress
    if net_decisions.allowed or net_decisions.denied:
        break
    time.sleep(1)

print(f'\n📜 Audit log (after ~{attempt + 1}s): {len(net_decisions.allowed)} allowed, {len(net_decisions.denied)} denied')
for tag, entries in (("✅", net_decisions.allowed), ("🚫", net_decisions.denied)):
    for e in entries:
        print(f'  {tag} {e.timestamp}  {e.method} {e.scheme}://{e.host}{e.path}')


# ── Step 14: Secrets ─────────────────────────────────────────────────────────
print("\n### Step 14: Secrets")

secret_id = f"demo-{uuid.uuid4().hex[:8]}"

client.upsert_secret(secret_id, {"API_KEY": "sk-test-123", "MODEL": "gpt-4"})
print(f'🔐 Upserted secret: {secret_id}')

names = [s.id for s in client.list_secrets()]
print(f'📚 {len(names)} secret(s) in group; demo present = {secret_id in names}')

print(f'🗝️ Keys: {client.list_secret_keys(secret_id)}')

peek = client.peek_secret(secret_id)
for k, v in (peek.values or {}).items():
    print(f'  {k} = {(v[:3] + "***") if v else ""}')

client.upsert_secret(secret_id, {"API_KEY": "sk-updated-456", "MODEL": "gpt-4o"})
peek = client.peek_secret(secret_id)
print(f'♻️ API_KEY now starts with {peek.values["API_KEY"][:6]}...')

client.delete_secret(secret_id)
print(f'🗑️ Deleted secret: {secret_id}')


# ── Step 15: Clean up ────────────────────────────────────────────────────────
print("\n### Step 15: Clean up")

# lab_sandboxes = list(client.list_sandboxes(labels=lab_labels))
# print(f'🔎 Found {len(lab_sandboxes)} sandbox(es) tagged {lab_labels}')
# for s in lab_sandboxes:
#     client.delete_sandbox(s.id)
#     print(f'  🗑️ Deleted sandbox: {s.id}')

# sandboxgroup_mgmt_client.delete_group(sandbox_group_name)
# print(f'🗑️ Deleted sandbox group: {sandbox_group_name}')

# Optionally delete the resource group (uncomment if you created the RG just for this lab):
# resource_mgmt_client.resource_groups.begin_delete(resource_group_name)
# print(f'🗑️ Deleting resource group (async): {resource_group_name}')

print("\n✅ Lab complete!")
