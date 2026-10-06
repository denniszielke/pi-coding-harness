# Pi Coding Harness

A coding harness that runs the [`pi`](https://www.npmjs.com/package/@earendil-works/pi-coding-agent)
coding agent inside an **Azure Container Apps Sandbox** — an isolated,
stateful, microVM-style execution boundary. The harness clones a GitHub repo
into the sandbox, injects short-lived credentials, runs `pi` non-interactively
against a natural-language task, then commits, pushes, and opens a pull request.

Everything dangerous — repo checkout, generated code, dependency restore,
tests, shell commands — stays **inside** the ephemeral sandbox. The sandbox is
deleted on exit.

```text
User / API / Queue
      │
      ▼
Coding Harness (this repo)
      │  create sandbox · inject repo + task + short-lived credentials
      ▼
Azure Container Apps Sandbox
      │  runs pi in a hardened dev image
      │  reads/writes code, runs tests, uses git/gh
      ▼
Branch · Pull Request · logs
```

## Contents

| File | What it does |
| --- | --- |
| [demo/01-getting-started.py](demo/01-getting-started.py) | Full sandbox lifecycle walkthrough (create, exec, files, ports, snapshots, volumes, egress). |
| [demo/02-yolo-coding.py](demo/02-yolo-coding.py) | Runs the **GitHub Copilot** CLI as a coding agent in a sandbox. |
| [demo/03-remote-mcp.py](demo/03-remote-mcp.py) | Builds and exposes a remote MCP server (Excalidraw) from a sandbox. |
| [demo/04-yolo-with-guardrails.py](demo/04-yolo-with-guardrails.py) | Same as 02, governed by the Microsoft Agent Governance Toolkit. |
| [demo/05-pi-coding.py](demo/05-pi-coding.py) | **The pi coding harness** — runs `pi` as the coding agent. |
| [demo/06-copilot-cli.py](demo/06-copilot-cli.py) | Opens an interactive **GitHub Copilot CLI** sandbox with proxy-injected GitHub authentication. |
| [demo/07-copilot-cli-yolo.py](demo/07-copilot-cli-yolo.py) | Runs **GitHub Copilot CLI** autonomously with all tools enabled, then pushes its changes and opens a pull request. |
| [scripts/deploy_managed_identity.sh](scripts/deploy_managed_identity.sh) | Provisions a user-assigned managed identity and grants it access to a Foundry model deployment (for `PI_PROVIDER=azure`). |
| [scripts/delete_sandbox.py](scripts/delete_sandbox.py) | Tears down sandboxes, disk images, and the sandbox group. |

## Prerequisites

- **Python 3.10+**
- **Azure CLI** signed in: `az login`
- An Azure subscription with permission to create resource groups and assign
  the `Container Apps SandboxGroup Data Owner` role.
- A **GitHub Personal Access Token (PAT)** with `repo` scope (and `workflow`
  if the target repo has workflows) — used for `git clone` / `push` and
  `gh pr create`.
- An **LLM provider** for `pi`, either:
  - an API key for Anthropic, OpenAI, or Google; **or**
  - an **Azure OpenAI / Foundry** deployment, authenticated with either an
    API key or a **managed identity** (see below).

## Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Sign in to Azure
az login

# 4. Create your .env (see below)
cp .env.example .env   # then edit it
```

### `.env` configuration

Create a `.env` file in the project root:

```dotenv
# ── GitHub ────────────────────────────────────────────────
PAT=github_pat_xxxxxxxxxxxxxxxxxxxxx
GITHUB_REPO=your-org/your-repo
GITHUB_BASE_BRANCH=main
# GITHUB_BRANCH=pi-feature-x          # optional; defaults to pi-<run_id>

# ── The task for pi ───────────────────────────────────────
CODING_PROMPT=Read task.md if present. Fix any obvious bugs, add a CHANGES.md summarising your changes, then run the tests.

# ── LLM provider for pi ───────────────────────────────────
PI_PROVIDER=anthropic                 # anthropic | openai | google
# PI_MODEL=sonnet                     # optional model pattern/id
ANTHROPIC_API_KEY=sk-ant-xxxxxxxx     # key for the chosen provider
# OPENAI_API_KEY=sk-xxxx              # if PI_PROVIDER=openai
# GEMINI_API_KEY=xxxx                 # if PI_PROVIDER=google

# ── Azure ─────────────────────────────────────────────────
RESOURCE_GROUP_NAME=aca-sandboxes-rg
SANDBOX_GROUP_NAME=pi-coding
LOCATION=westus3

# ── Optional egress allow-list ────────────────────────────
# EGRESS_EXTRA_HOSTS=*.microsoft.com raw.githubusercontent.com
```

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PAT` | ✅ | — | GitHub PAT for git + `gh`. |
| `GITHUB_REPO` | ✅ | — | Target repo as `owner/repo`. |
| `GITHUB_BASE_BRANCH` | | `main` | Branch to clone from. |
| `GITHUB_BRANCH` | | `pi-<run_id>` | Branch to push to. |
| `CODING_PROMPT` | | built-in default | Natural-language task for pi. |
| `PI_PROVIDER` | | `anthropic` | `anthropic`, `openai`, `google`, or `azure`. |
| `PI_MODEL` | | provider default | Model pattern/id passed to `pi --model`. |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` | ✅ (one) | — | API key for the chosen provider (non-Azure). |
| `EGRESS_EXTRA_HOSTS` | | `*.microsoft.com` | Extra hosts allowed after egress lockdown. |
| `RESOURCE_GROUP_NAME` | | `aca-sandboxes-rg` | Azure resource group. |
| `SANDBOX_GROUP_NAME` | | `pi-coding` | Sandbox group name. |
| `LOCATION` | | `westus3` | Azure region. |

### Azure OpenAI / Foundry with a managed identity

Set `PI_PROVIDER=azure` to run pi against an Azure OpenAI or Foundry-hosted
deployment. The harness reads the resource coordinates **already in your
`.env`** — `AZURE_OPENAI_ENDPOINT`, `AZURE_AI_MODEL_DEPLOYMENT_NAME`, and
`AZURE_AI_PROJECT_ID` — so no Azure-specific renaming is needed. When no API
key is supplied it authenticates with a **managed identity** — no key ever
touches the sandbox:

1. Attaches a managed identity to the sandbox group (a pre-provisioned
   user-assigned identity when `AZURE_MANAGED_IDENTITY_RESOURCE_ID` is set,
   otherwise a SystemAssigned one) so the sandbox inherits it.
2. Ensures the identity has **`Cognitive Services OpenAI User`** on the Foundry
   account (pre-granted by the deployment script, or granted at runtime when
   the account scope is derivable from `AZURE_AI_PROJECT_ID`).
3. Configures pi (via `~/.pi/agent/models.json`) to call the deployment with a
   short-lived **Entra token** (`Authorization: Bearer …`) fetched from inside
   the sandbox at request time.

Existing `.env` values used automatically:

| Variable (in `.env`) | Used for |
| --- | --- |
| `AZURE_AI_PROJECT_ENDPOINT` | Foundry project endpoint (preferred); normalized to the account's `/openai/v1`. |
| `AZURE_OPENAI_ENDPOINT` | direct Azure OpenAI endpoint, used when no project endpoint is set. |
| `AZURE_AI_MODEL_DEPLOYMENT_NAME` | deployment name = the pi model id. |
| `AZURE_AI_PROJECT_ID` | account scope for the role grant (derived). |

The harness accepts the Foundry **project endpoint**
(`https://<res>.services.ai.azure.com/api/projects/<proj>`) directly and
normalizes it to the account's OpenAI v1 route
(`https://<res>.services.ai.azure.com/openai/v1`), which serves the project's
model deployments.

Optional overrides:

| Variable | Default | Description |
| --- | --- | --- |
| `AZURE_OPENAI_BASE_URL` | project/openai endpoint | Force a specific base URL (overrides both endpoints). |
| `AZURE_OPENAI_DEPLOYMENT` | `AZURE_AI_MODEL_DEPLOYMENT_NAME` | Override the deployment. |
| `AZURE_OPENAI_API` | `openai-responses` | `openai-responses` or `openai-completions`. |
| `AZURE_OPENAI_ACCOUNT_RESOURCE_ID` | derived from project id | Account scope for the runtime role grant. |
| `AZURE_MANAGED_IDENTITY_CLIENT_ID` | — | Client id of the user-assigned MI. |
| `AZURE_MANAGED_IDENTITY_RESOURCE_ID` | — | ARM id of a pre-provisioned user-assigned MI to attach to the sandbox group. |
| `AZURE_OPENAI_API_KEY` | — | Supply to use key auth instead of a managed identity. |

#### Recommended: pre-provision the identity with the deployment script

If the Foundry project and model deployment already exist, provision a
**user-assigned** managed identity and grant it access up front with
[scripts/deploy_managed_identity.sh](scripts/deploy_managed_identity.sh). It
reads all resource coordinates from `.env` (`AZURE_AI_PROJECT_ID`,
`AZURE_OPENAI_ENDPOINT`, `AZURE_AI_MODEL_DEPLOYMENT_NAME`, …):

```bash
./scripts/deploy_managed_identity.sh
```

It creates the identity, grants it `Cognitive Services OpenAI User` on the
Foundry **account** (which governs the model deployments) and `Foundry User`
on the **project**, then prints only the values you still need to add to
`.env`:

```dotenv
PI_PROVIDER="azure"
AZURE_MANAGED_IDENTITY_CLIENT_ID="<client-id>"
AZURE_MANAGED_IDENTITY_RESOURCE_ID="<identity-arm-id>"
```

The harness then attaches that identity to the sandbox group and skips any
further role grants.

> Without the deployment script, the harness falls back to a SystemAssigned
> identity and grants the role at runtime — which requires the signed-in user
> to have `Microsoft.Authorization/roleAssignments/write` (e.g. **Owner** or
> **User Access Administrator**) on the Foundry account.

## Run the pi harness

```bash
python demo/05-pi-coding.py
```

For an interactive GitHub Copilot CLI session using the same `.env`, run:

```bash
python demo/06-copilot-cli.py
```

This scenario uses `PAT`, `GH_TOKEN`, or `GITHUB_TOKEN` when set; otherwise it
automatically reads the active token from `gh auth token`. Run `gh auth login`
once if the GitHub CLI is not already authenticated.

The scenario adapts the Azure Samples Copilot CLI policy by replacing its PAT
placeholders only in memory. The sandbox proxy injects authentication headers;
the PAT is never written to the sandbox filesystem or the checked-in policy.

To run the same CLI non-interactively as an autonomous coding agent, configure
`GITHUB_REPO` and `CODING_PROMPT`, then run:

```bash
python demo/07-copilot-cli-yolo.py
```

The YOLO scenario clones the repository, creates a `copilot-<run_id>` branch,
runs Copilot with `--allow-all-tools`, commits and pushes any changes, and opens
a pull request. The sandbox is always deleted afterward.

What happens:

1. **Provision** — ensures the resource group and sandbox group exist, and
   assigns you `Container Apps SandboxGroup Data Owner`.
2. **Boot** — creates an Ubuntu sandbox (2 CPU, 4 GB).
3. **Install** — git, `gh`, Node.js 22, and `pi` (from npm).
4. **Inject credentials** — the GitHub PAT (`~/.netrc` + `GH_TOKEN`) and the
   LLM API key, both only inside the sandbox.
5. **Lock egress** — deny-by-default; only GitHub, package registries,
   `pi.dev`, and the chosen LLM provider host are allowed.
6. **Clone** the repo and check out a new branch.
7. **Run pi** — `pi --offline -a -p "<your task>"` in print mode. In print
   mode pi runs its tools (`read`, `write`, `edit`, `bash`, `grep`, `find`,
   `ls`) with no permission popups — the sandbox is the safety boundary.
8. **Commit, push, PR** — commits changes, pushes the branch, opens a PR.
9. **Cleanup** — waits for you to press Enter, then deletes the sandbox.

## Security model

- Credentials are **never baked into an image** — they are injected as
  runtime secrets into a single ephemeral sandbox and deleted with it.
- `pi`'s API key and the GitHub PAT are **separate credentials** with
  different blast radii.
- **Egress is deny-by-default.** Only the hosts required for the task are
  allowed; add more with `EGRESS_EXTRA_HOSTS`.
- The agent's shell runs **inside** the sandbox, not on your machine.
- For an additional policy layer (blocking destructive/exfiltration actions),
  see the governed variant in [demo/04-yolo-with-guardrails.py](demo/04-yolo-with-guardrails.py).

## Cleanup

The harness deletes its sandbox on exit. To remove the sandbox group, disk
images, and any leaked sandboxes:

```bash
python scripts/delete_sandbox.py
# also delete the resource group:
python scripts/delete_sandbox.py --delete-resource-group
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `az CLI not logged in` | Run `az login`. |
| `PAT is not set` / `GITHUB_REPO is not set` | Add them to `.env`. |
| `<KEY> is not set (required for PI_PROVIDER=...)` | Set the API key env var that matches `PI_PROVIDER`. |
| PR creation skipped | The branch is still pushed — open the PR from the compare link, or check the PAT's Pull requests permission. |
| Role assignment delay | The harness waits 60s for propagation; re-run if you hit a transient auth error. |
