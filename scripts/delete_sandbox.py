"""Delete the Shopping Claw sandbox resources.

Tears down what ``src/agents/narrator/shopping_claw.py`` provisions: any running
sandboxes, the private disk images, and the sandbox group itself. The shared
resource group and the user-assigned managed identity are left in place by
default (pass ``--delete-resource-group`` to also remove the resource group).

Usage::

    python scripts/delete_sandbox.py
    python scripts/delete_sandbox.py --delete-resource-group

Environment variables (from ``.env``):
  RESOURCE_GROUP_NAME   sandbox resource group (default: aca-sandboxes-rg)
  SANDBOX_GROUP_NAME    sandbox group name     (default: shopping-claw)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from azure.containerapps.sandbox import (
    SandboxGroupClient,
    SandboxGroupManagementClient,
    endpoint_for_region,
)
from azure.identity import AzureCliCredential
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)

RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "aca-sandboxes-rg")
SANDBOX_GROUP_NAME = os.getenv("SANDBOX_GROUP_NAME", "shopping-claw")


def _subscription_id() -> str:
    try:
        proc = subprocess.run(
            "az account show -o json",
            capture_output=True, text=True, check=True, shell=True,
        )
        return json.loads(proc.stdout)["id"]
    except subprocess.CalledProcessError as e:
        sys.exit(f"❌ az CLI not logged in. Run `az login` first.\n{e.stderr}")


def delete(delete_resource_group: bool = False) -> int:
    subscription_id = _subscription_id()
    cred = AzureCliCredential()
    mgmt = SandboxGroupManagementClient(
        cred, subscription_id=subscription_id, resource_group=RESOURCE_GROUP_NAME
    )

    group = next(
        (g for g in mgmt.list_groups() if g.name == SANDBOX_GROUP_NAME), None
    )
    if group is None:
        print(
            f"Sandbox group '{SANDBOX_GROUP_NAME}' not found in "
            f"'{RESOURCE_GROUP_NAME}' — nothing to delete."
        )
    else:
        client = SandboxGroupClient(
            endpoint_for_region(group.location),
            cred,
            subscription_id=subscription_id,
            resource_group=RESOURCE_GROUP_NAME,
            sandbox_group=SANDBOX_GROUP_NAME,
        )

        # 1) Delete any live sandboxes in the group.
        try:
            for sb in client.list_sandboxes():
                sid = getattr(sb, "id", None) or getattr(sb, "sandbox_id", None)
                try:
                    client.delete_sandbox(sid)
                    print(f"  🗑️  Deleted sandbox {sid}")
                except Exception as e:  # noqa: BLE001
                    print(f"  ⚠️  sandbox delete failed ({sid}): {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠️  could not list sandboxes: {e}")

        # 2) Delete the private disk images.
        try:
            for img in client.list_disk_images():
                iid = getattr(img, "id", None) or getattr(img, "name", None)
                try:
                    client.delete_disk_image(iid)
                    print(f"  🗑️  Deleted disk image {iid}")
                except Exception as e:  # noqa: BLE001
                    print(f"  ⚠️  disk image delete failed ({iid}): {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠️  could not list disk images: {e}")

        # 3) Delete the sandbox group.
        print(f"Deleting sandbox group '{SANDBOX_GROUP_NAME}'...")
        mgmt.begin_delete_group(SANDBOX_GROUP_NAME).result()
        print(f"✅ Deleted sandbox group '{SANDBOX_GROUP_NAME}'.")

        client.close()

    mgmt.close()

    if delete_resource_group:
        print(f"Deleting resource group '{RESOURCE_GROUP_NAME}'...")
        subprocess.run(
            ["az", "group", "delete", "-n", RESOURCE_GROUP_NAME, "--yes", "--no-wait"],
            check=True,
        )
        print(f"✅ Resource group '{RESOURCE_GROUP_NAME}' deletion started (no-wait).")

    cred.close()
    return 0


if __name__ == "__main__":
    sys.exit(delete(delete_resource_group="--delete-resource-group" in sys.argv[1:]))
