# AGENTS.md

Context for coding agents working in the **pi-coding-harness** repo. This
project provisions Azure Container Apps Sandboxes and runs coding agents
(`pi`, GitHub Copilot CLI) inside them.

## Project layout

- `demo/` — runnable harness scripts (one scenario each).
- `scripts/` — teardown / maintenance utilities.
- `requirements.txt` — root dependencies (Azure SDK + sandbox client).
- `demo/requirements.txt` — extra deps for the OpenAI Agents SDK swarm demo.
- `.env` — local configuration (never commit; not tracked).

## Setup commands

```bash
# Create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Sign in to Azure (required before running any demo)
az login
```

## Run commands

```bash
# The pi coding harness
python demo/05-pi-coding.py

# Other scenarios
python demo/01-getting-started.py        # sandbox lifecycle walkthrough
python demo/02-yolo-coding.py            # GitHub Copilot CLI agent
python demo/03-remote-mcp.py             # host a remote MCP server
python demo/04-yolo-with-guardrails.py   # governed Copilot agent
```

## Cleanup commands

```bash
python scripts/delete_sandbox.py                          # delete sandboxes + group
python scripts/delete_sandbox.py --delete-resource-group  # also delete the RG
```

## Azure managed identity (for PI_PROVIDER=azure)

```bash
# Provision a user-assigned MI and grant it access to the Foundry deployment.
# Reads AZURE_AI_PROJECT_ID / AZURE_OPENAI_ENDPOINT / AZURE_AI_MODEL_DEPLOYMENT_NAME
# from .env, then prints the AZURE_* vars to paste back into .env.
./scripts/deploy_managed_identity.sh
```

## Validation commands

```bash
# Byte-compile a script to catch syntax errors (no Azure calls)
python3 -m py_compile demo/05-pi-coding.py

# Compile every demo
python3 -m py_compile demo/*.py scripts/*.py
```

There is no test suite; validate changes with `py_compile` and by running the
relevant demo against a scratch repo.

## The `pi` CLI (used by demo/05)

`pi` is installed inside the sandbox via
`npm install -g --ignore-scripts @earendil-works/pi-coding-agent`.

```bash
pi -p "prompt"                 # print mode: non-interactive, runs and exits
cat notes.md | pi -p "prompt"  # piped stdin is merged into the prompt
pi -a -p "prompt"              # trust project-local files for this run
pi --offline -p "prompt"       # skip pi.dev startup network calls
pi --model sonnet -p "prompt"  # pick a model
pi --tools read,grep,find,ls -p "review only"   # allowlist tools (read-only)
pi --version                   # print version
```

Built-in tools: `read`, `write`, `edit`, `bash`, `grep`, `find`, `ls`.
In print mode (`-p`) pi runs tools without permission popups, so it must run
inside a container/sandbox.

Auth: pi reads a provider API key from the environment
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY`). For Azure OpenAI /
Foundry (`PI_PROVIDER=azure`), demo/05 writes `~/.pi/agent/models.json` and can
authenticate with a managed-identity Entra token instead of a key.

## Conventions

- Load config from the root `.env` with `python-dotenv`; do not hard-code
  secrets. Never print secret values.
- Each demo is a standalone script with a `main()` entrypoint and a `finally`
  block that guarantees sandbox cleanup.
- Inject credentials only into the ephemeral sandbox; keep egress
  deny-by-default and allow the minimum hosts needed.
- Pin exact versions for `azure-*` SDKs where the samples already pin them;
  use `>=` only where the existing file does.
- Match the existing style: emoji status prints, `### Step N:` section headers,
  and the `_exec_check` / `_exec_stream` helpers for sandbox commands.
