#!/usr/bin/env bash
#
# deploy_managed_identity.sh
#
# Provisions a USER-ASSIGNED managed identity and grants it the permissions
# needed to call an already-existing Azure AI Foundry model deployment, so the
# pi coding harness (demo/05-pi-coding.py) can authenticate to the model with
# an Entra token instead of an API key.
#
# It assumes the Foundry project and the model deployment already exist. It
# reads all resource coordinates from the project's .env file:
#
#   AZURE_SUBSCRIPTION_ID          subscription
#   AZURE_AI_PROJECT_ID            ARM id of the Foundry project (account is derived)
#   AZURE_OPENAI_ENDPOINT          data-plane endpoint (…openai.azure.com)
#   AZURE_AI_MODEL_DEPLOYMENT_NAME model deployment to use
#   AZURE_ENV_NAME                 used to name the identity
#   AZURE_LOCATION                 region for the identity
#
# What it does:
#   1. Creates (idempotently) a user-assigned managed identity.
#   2. Grants it "Cognitive Services OpenAI User" on the Foundry ACCOUNT — the
#      scope that governs the .openai.azure.com inference endpoint and every
#      deployment under it (the project inherits account-level data-plane roles).
#   3. Grants it "Azure AI User" on the Foundry PROJECT (best-effort) for
#      Foundry-native (…services.ai.azure.com) access.
#   4. Prints the env vars to add to .env for the harness.
#
# Usage:
#   ./scripts/deploy_managed_identity.sh
#   PI_MANAGED_IDENTITY_NAME=id-my-pi ./scripts/deploy_managed_identity.sh
#
set -euo pipefail

# ── Locate and read the .env ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "❌ .env not found at $ENV_FILE" >&2
  exit 1
fi

# Read a single KEY=value from .env, stripping surrounding quotes.
read_env() {
  grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'
}

require() {
  if [[ -z "${2:-}" ]]; then
    echo "❌ $1 is not set in $ENV_FILE" >&2
    exit 1
  fi
}

SUBSCRIPTION_ID="$(read_env AZURE_SUBSCRIPTION_ID)"
PROJECT_ID="$(read_env AZURE_AI_PROJECT_ID)"
OPENAI_ENDPOINT="$(read_env AZURE_OPENAI_ENDPOINT)"
DEPLOYMENT_NAME="$(read_env AZURE_AI_MODEL_DEPLOYMENT_NAME)"
ENV_NAME="$(read_env AZURE_ENV_NAME)"
LOCATION="$(read_env AZURE_LOCATION)"

require AZURE_SUBSCRIPTION_ID "$SUBSCRIPTION_ID"
require AZURE_AI_PROJECT_ID "$PROJECT_ID"
require AZURE_OPENAI_ENDPOINT "$OPENAI_ENDPOINT"
require AZURE_AI_MODEL_DEPLOYMENT_NAME "$DEPLOYMENT_NAME"

# ── Derive the account + resource group from the project ARM id ──────────────
# .../resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<acct>/projects/<proj>
ACCOUNT_ID="${PROJECT_ID%%/projects/*}"                       # strip /projects/<proj>
RESOURCE_GROUP="$(sed -E 's#.*/resourceGroups/([^/]+)/.*#\1#' <<<"$PROJECT_ID")"
ACCOUNT_NAME="$(sed -E 's#.*/accounts/([^/]+).*#\1#' <<<"$ACCOUNT_ID")"

MI_NAME="${PI_MANAGED_IDENTITY_NAME:-id-pi-coding-${ENV_NAME:-foundry}}"
LOCATION="${LOCATION:-swedencentral}"

OPENAI_ROLE="Cognitive Services OpenAI User"
PROJECT_ROLE="Azure AI User"

echo "🔧 Deploy managed identity for the pi coding harness"
echo "   Subscription:   $SUBSCRIPTION_ID"
echo "   Resource group: $RESOURCE_GROUP"
echo "   Foundry account:$ACCOUNT_NAME"
echo "   Account scope:  $ACCOUNT_ID"
echo "   Project scope:  $PROJECT_ID"
echo "   Deployment:     $DEPLOYMENT_NAME"
echo "   Identity name:  $MI_NAME ($LOCATION)"
echo

az account set --subscription "$SUBSCRIPTION_ID"

# ── 1. Create the user-assigned managed identity (idempotent) ────────────────
echo "### Step 1: Create user-assigned managed identity"
az identity create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$MI_NAME" \
  --location "$LOCATION" \
  --output none

MI_CLIENT_ID="$(az identity show -g "$RESOURCE_GROUP" -n "$MI_NAME" --query clientId -o tsv)"
MI_PRINCIPAL_ID="$(az identity show -g "$RESOURCE_GROUP" -n "$MI_NAME" --query principalId -o tsv)"
MI_RESOURCE_ID="$(az identity show -g "$RESOURCE_GROUP" -n "$MI_NAME" --query id -o tsv)"
echo "  ✅ clientId=$MI_CLIENT_ID"
echo "     principalId=$MI_PRINCIPAL_ID"

# ── Helper: assign a role, retrying while the new MI principal replicates ─────
assign_role() {
  local role="$1" scope="$2" fatal="$3"
  local attempt
  for attempt in $(seq 1 12); do
    if az role assignment create \
        --assignee-object-id "$MI_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "$role" \
        --scope "$scope" \
        --output none 2>/tmp/role_err; then
      echo "  ✅ Assigned '$role'"
      return 0
    fi
    if grep -qiE "RoleAssignmentExists|already exists" /tmp/role_err; then
      echo "  ♻️  '$role' already assigned"
      return 0
    fi
    if grep -qiE "PrincipalNotFound|does not exist in the directory" /tmp/role_err; then
      sleep 5
      continue
    fi
    if [[ "$fatal" == "fatal" ]]; then
      echo "  ❌ Failed to assign '$role':" >&2
      cat /tmp/role_err >&2
      exit 1
    fi
    echo "  ⚠️  Could not assign '$role' (non-fatal): $(tr -d '\n' </tmp/role_err | cut -c1-200)"
    return 0
  done
  if [[ "$fatal" == "fatal" ]]; then
    echo "  ❌ '$role' never succeeded (principal replication timed out)" >&2
    exit 1
  fi
}

# ── 2. Grant inference access on the account (required) ──────────────────────
echo
echo "### Step 2: Grant '$OPENAI_ROLE' on the Foundry account"
assign_role "$OPENAI_ROLE" "$ACCOUNT_ID" fatal

# ── 3. Grant Foundry project access (best-effort) ────────────────────────────
echo
echo "### Step 3: Grant '$PROJECT_ROLE' on the Foundry project"
assign_role "$PROJECT_ROLE" "$PROJECT_ID" nonfatal

# ── 4. Emit the harness configuration ────────────────────────────────────────
echo
echo "========================================================================"
echo "✅ Managed identity ready. Add these to your .env for demo/05-pi-coding.py:"
echo "========================================================================"
cat <<EOF
PI_PROVIDER="azure"
AZURE_MANAGED_IDENTITY_CLIENT_ID="$MI_CLIENT_ID"
AZURE_MANAGED_IDENTITY_RESOURCE_ID="$MI_RESOURCE_ID"
EOF
echo "========================================================================"
echo
echo "The harness reads AZURE_OPENAI_ENDPOINT ($OPENAI_ENDPOINT) and"
echo "AZURE_AI_MODEL_DEPLOYMENT_NAME ($DEPLOYMENT_NAME) directly from .env, and"
echo "derives the account scope from AZURE_AI_PROJECT_ID — no extra vars needed."
echo "It attaches this user-assigned identity to the sandbox group; roles are"
echo "already assigned here, so it performs no further role grants."
