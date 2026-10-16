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
| [demo/07-copilot-cli-yolo.py](demo/07-copilot-cli-yolo.py) | Runs **GitHub Copilot CLI** autonomously with all permissions enabled, then pushes its changes and opens a pull request. |
| [demo/08-copilot-squad.py](demo/08-copilot-squad.py) | Runs the existing **Squad** team on Copilot CLI to implement task-tracker's late-notification PRD, validates the project, then pushes and opens a pull request. |
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
runs Copilot with `--allow-all` (tools, filesystem paths, and URLs), commits
and pushes any changes, and opens a pull request. These approvals apply only
inside the ephemeral sandbox; the deny-default egress policy still restricts
network access. Before applying that policy, the harness installs and checks
Python pip/venv support and Poppler's `pdftotext` utility so the agent can create
virtual environments and extract PDF text without bootstrapping system tools.
The sandbox is always deleted afterward.

### Squad on Copilot CLI

Run the existing Squad team in
[`denniszielke/task-tracker`](https://github.com/denniszielke/task-tracker)
against its
[`late-notification-prd.md`](https://github.com/denniszielke/task-tracker/blob/main/late-notification-prd.md):

```bash
python demo/08-copilot-squad.py
```

Run this command from the harness repository root on your local machine.
No prompt argument is required: the script defaults to `denniszielke/task-tracker`
and asks Squad to implement `late-notification-prd.md`.

To append specific instructions, set `SQUAD_PROMPT`:

```bash
SQUAD_PROMPT="Prioritize deterministic tests for retries, stale events, and shop isolation." \
  python demo/08-copilot-squad.py
```

If `SQUAD_PROMPT` is also set in `.env`, that value takes precedence over the
inline environment variable.

The demo installs Node.js 22 and `@bradygaster/squad-cli@0.13.1` (matching the
repository's coordinator), alongside Copilot CLI and the Python/PDF toolchain.
It clones the target repo onto a new `squad-<run_id>` branch, verifies the PRD
and existing Squad coordinator/team, and installs the locked project dependencies
with `npm ci`. It does **not** reinitialize or upgrade the repository's Squad team.

The npm CLI installation and Copilot launch follow the
[public Squad installation guide](https://bradygaster.github.io/squad/docs/get-started/installation/)
and [Copilot workflow](https://github.com/bradygaster/squad#readme).
All dependency downloads run **inside the sandbox**, not on your local machine.
The installer explicitly selects `https://registry.npmjs.org/`. Before each
project install it also rewrites the task-tracker lockfile's known
`ms-feed-25.pkgs.visualstudio.com/1es-public/_packaging/npm-public/npm/registry/`
tarball prefix to the public registry, preserving package versions and integrity
hashes. A registry flag alone does not override those pinned tarball URLs.
This lockfile correction is included in the resulting PR; other custom registry
URLs are not rewritten or automatically allowed through egress.

The task is run through
`copilot --agent=squad --yolo --prompt="..."`, following Squad's documented
Copilot launch flags. Folder trust is recorded only in the ephemeral sandbox's
Copilot configuration, rather than using the version-dependent `--trust-folder`
flag. The `--prompt=` form keeps the entire prompt as one option value, including
multiline content or text beginning with a dash.

Concrete prompt command, run from the cloned task-tracker repository **inside
the sandbox**, after the harness has installed dependencies and configured trust:

```bash
copilot --agent=squad --yolo \
  --prompt="Squad, read late-notification-prd.md and late-filter-prd.md in full. Use the existing team, routing, and decisions in .squad; do not reinitialize the team. Delegate planning and review to Lead, event processing and dependency traversal to Backend, notification UI to Frontend, and deterministic acceptance tests to Tester. Implement the late-notification PRD end to end, including direct and transitive job impacts, shop-specific notifications, acknowledgements, revisions, retries, and duplicate/stale-event handling. Preserve the Late Delivery Filter and existing offline behavior. Record decisions for open questions and explicitly identify unmet production requirements. Run npm test, npm run lint, and npm run build; fix failures caused by your changes. Keep package-lock.json synchronized. Stay on the current branch and do not commit, push, open a PR, or deploy; the harness handles publishing. Finish with changes made, test results, and remaining PRD gaps."
```

To run the complete provision/install/Squad/validate/publish workflow from your
local machine instead, use `python demo/08-copilot-squad.py` as shown above;
the harness supplies its built-in PRD implementation prompt automatically.

The coordinator is asked to delegate implementation, testing, and review to
the existing specialists, preserve the Late Delivery Filter and offline behavior,
and explicitly report any unmet production requirements. The harness reruns
`npm ci`, `npm test`, `npm run lint`, and `npm run build` before it will commit,
push, or open a PR. Passing these checks is not a claim that every PRD acceptance
criterion has been met; review Squad's final summary and the PR.

| Variable | Default | Description |
| --- | --- | --- |
| `SQUAD_GITHUB_REPO` | `denniszielke/task-tracker` | Target repo; must already contain the Squad team, coordinator, PRD, and npm lockfile. |
| `SQUAD_BASE_BRANCH` | `main` | Branch to clone. |
| `SQUAD_BRANCH` | `squad-<run_id>` | New branch for the implementation. |
| `SQUAD_PRD` | `late-notification-prd.md` | Repository-relative PRD path. |
| `SQUAD_PROMPT` | empty | Additional instructions appended to the PRD implementation prompt. |

These task settings intentionally do not inherit `GITHUB_REPO`, `GITHUB_BRANCH`,
`GITHUB_BASE_BRANCH`, or `CODING_PROMPT` from other demos. GitHub credentials,
Azure settings, and `EGRESS_EXTRA_HOSTS` use the same configuration as Demo 07.
Egress remains deny-by-default, with `registry.npmjs.org` additionally allowed
for npm dependencies. Credentials remain process-scoped, and the sandbox is
deleted on exit.

### Pi harness steps

What happens when running Demo 05:

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
| Copilot CLI: `Denied, no one to approve` | In the YOLO sandbox, use `--allow-all`, not just `--allow-all-tools`: filesystem paths and URLs have separate approval checks. |
| `No module named ensurepip` / venv creation fails | Install `python3-venv` (matching the interpreter version) and `python3-pip` before egress lockdown, then recreate any failed virtual environment. Demo 07 installs these during setup. |
| `pdftotext: command not found` | Install `poppler-utils` before egress lockdown. Demo 07 includes it in the toolchain. |
| `ServiceResponseError: Connection reset by peer` while starting the background agent | Demo 07 launches the background wrapper with `nohup` and redirects all its standard streams so the exec request can return immediately; output is then polled from the log. Cleanup messages can precede this traceback because cleanup runs in `finally`. |
