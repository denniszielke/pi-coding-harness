Short version

Yes — this can work nicely.

Think of it as:

Plain Text
1
User / API / Queue
2
|
3
v
4
Coding Harness Orchestrator
5
|
6
| create / resume sandbox
7
| inject repo + task + short-lived credentials
8
v
9
Azure Container Apps Sandbox
10
|
11
| runs pi in a hardened dev image
12
| reads/writes code, runs tests, uses git/gh
13
v
14
Patch / artifact / pull request / logs
Show more lines

Quickstart · Documentation · Pi shows that Pi is a terminal-based coding agent installed via npm, started inside a project directory, and given tools such as read, write, edit, and bash; it can also run one-shot prompts with pi -p, which is useful for a harness-driven workflow. Azure Container Apps Sandboxes overview (preview) says ACA Sandboxes are first-class Microsoft.App/SandboxGroups resources with isolated sandboxes, OCI image support, suspend/resume, snapshots, volumes, ports, files, egress policies, and lifecycle control — exactly the substrate you want for stateful coding-agent execution.

Recommended architecture
1. Build a custom “Pi coding sandbox” image

Create an OCI image that contains:

Node.js / npm
Pi installed globally
git, GitHub CLI, Azure CLI if needed
your preferred runtimes: Python, .NET, Java, Node, Bun, uv, etc.
test tooling and repo-specific bootstrap scripts
a non-root execution user

Pi’s quickstart says it is installed as:

Shell
1
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
Show more lines

and then started in the target project directory with pi.

So your image would roughly look like:

Dockerfile
1
FROM mcr.microsoft.com/devcontainers/base:ubuntu
2
 
3
RUN apt-get update && apt-get install -y \
4
git curl jq ripgrep fd-find ca-certificates \
5
&& rm -rf /var/lib/apt/lists/*
6
 
7
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
8
&& apt-get install -y nodejs
9
 
10
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent
11
 
12
RUN useradd -ms /bin/bash coder
13
USER coder
14
WORKDIR /workspace
Show more lines
2. Use ACA Sandboxes as the per-task execution boundary

Use a sandbox group as the management boundary for your harness. The public documentation says sandbox groups scope sandboxes, disk images, snapshots, volumes, and secrets; individual sandboxes then run from disk images or snapshots and have their own CPU, memory, disk, and network boundary.

For your coding harness, I would map:

Concept	ACA Sandbox mappingCoding task	One sandbox instance
Base developer environment	Disk image from your Pi OCI image
Long-running agent workspace	Suspended sandbox or snapshot
Shared input/output	Azure Blob volume
Build cache / repo workspace	Data Disk volume
Network policy	Sandbox egress policy
Web preview	Exposed sandbox port
Audit trail	Harness logs + Pi logs + git history
3. Run Pi inside the sandbox, not beside it

The cleanest pattern is to run Pi inside the sandbox, because Pi’s default tools can read, write, edit, and execute shell commands in its current working directory. That keeps the dangerous part — repo checkout, generated code, dependency restore, tests, shell commands — inside the isolated compute boundary.

Your harness should not execute arbitrary model-generated commands itself. It should:

create or resume the sandbox,
copy task instructions into /workspace/task.md,
clone or mount the target repo,
inject short-lived credentials,
call Pi non-interactively,
collect output, diffs, logs, test results,
create a pull request or return a patch,
suspend, snapshot, or delete the sandbox.

Example sandbox command:

Shell
1
cd /workspace/repo
2
 
3
pi -p "
4
You are working on this repository.
5
Read task.md.
6
Implement the requested change.
7
Run the project's checks.
8
If successful, create a concise summary of changed files and test results.
9
"
Show more lines

Pi’s quickstart explicitly supports non-interactive prompts with pi -p, piping input into Pi, session continuation, and project instructions through AGENTS.md, which makes it suitable for harness automation.

Harness flow

A practical first implementation:

Plain Text
1
1. Receive task
2
- repo URL
3
- branch
4
- issue/task text
5
- expected checks
6
- allowed network targets
7
 
8
2. Prepare sandbox
9
- create sandbox from Pi disk image
10
- attach data disk or blob volume
11
- apply egress allow-list
12
- inject GitHub token as runtime secret
13
 
14
3. Bootstrap repo
15
- git clone
16
- checkout branch
17
- write AGENTS.md
18
- write task.md
19
 
20
4. Run Pi
21
- pi -p "Implement task.md and run checks"
22
- stream logs back to orchestrator
23
 
24
5. Validate
25
- run deterministic checks outside the model loop if possible
26
- collect git diff
27
- collect test output
28
 
29
6. Publish result
30
- create branch
31
- commit changes
32
- open PR
33
- return PR link and summary
34
 
35
7. Lifecycle
36
- snapshot if you want continuity
37
- delete if task is done
Show more lines

The internal build2026 and Build 2026 Recap - Deep Dive  Data & AI material positions ACA Sandboxes as fast, isolated, stateful compute for agent workflows, AI code execution, persistent workspaces, and platform building; that matches the exact “coding harness” pattern.

Why ACA Sandboxes instead of Dynamic Sessions?

Use ACA Sandboxes for this scenario, not only Dynamic Sessions.

Dynamic Sessions are good when you want a managed request-routed execution endpoint. Sandboxes are better when you want direct lifecycle control: create, suspend, resume, delete, manage files, ports, egress, snapshots, volumes, and persistent state. Azure Container Apps Sandboxes overview (preview) explicitly contrasts the two: Dynamic Sessions are ephemeral and managed by a pool, while Sandboxes are stateful and directly controlled by SDK/CLI with snapshots and volumes.

For a coding harness, that matters because coding agents need:

repo workspace continuity,
build cache persistence,
resumable long-running tasks,
port exposure for app previews,
controlled network egress,
explicit deletion after task completion,
reproducible snapshots for debugging.

The Azure Container Apps Office Hours transcript also describes Sandboxes as a broader platform than Dynamic Sessions, with improved bring-your-own-image experience and better fit for custom tooling. The meeting was transcribed.

Security model I would use

Do not bake credentials into the image.

Use this pattern instead:

Plain Text
1
Managed identity / harness identity
2
|
3
v
4
fetch short-lived GitHub credential
5
|
6
v
7
inject into sandbox env/secret for one run
8
|
9
v
10
delete / revoke after PR creation
Show more lines

Important controls:

use Container Apps SandboxGroup Data Owner only for identities that create/manage sandboxes; Microsoft Learn states this role is required for creating or managing sandboxes.
use a separate low-privilege identity for the harness runtime;
prefer GitHub App installation tokens or fine-scoped short-lived tokens over broad PATs;
restrict egress to GitHub, package registries, and required Azure endpoints;
prevent access to host credentials by design — the sandbox should only receive explicit runtime secrets;
delete or snapshot intentionally after each task;
store logs and diffs outside the sandbox before teardown.

Azure Container Apps Sandboxes overview (preview) says networking controls include egress policies with domain-based allow/deny rules and CIDR-based rules.

Minimal prototype shape

You can start with three components:

A. Harness API

A small API, for example in Container Apps:

Plain Text
1
POST /tasks
2
{
3
"repo": "https://github.com/org/repo",
4
"branch": "main",
5
"task": "Add support for ...",
6
"checks": ["npm test", "npm run lint"]
7
}
Show more lines
B. Sandbox worker image

Your Pi-enabled dev image.

It should include:

Plain Text
1
/pi-entrypoint.sh
2
/bootstrap-repo.sh
3
/run-pi-task.sh
4
/publish-pr.sh
Show more lines
C. Result contract

The sandbox writes a structured result:

JSON
1
{
2
"status": "success",
3
"branch": "agent/task-123",
4
"pullRequestUrl": "https://github.com/org/repo/pull/123",
5
"summary": "Implemented ...",
6
"checks": [
7
{ "name": "npm test", "status": "passed" }
8
],
9
"changedFiles": [
10
"src/foo.ts",
11
"tests/foo.test.ts"
12
]
13
}
Show more lines
My concrete recommendation

Start with Pi inside ACA Sandboxes, controlled by a lightweight orchestrator. Use sandbox snapshots only when you want agent continuity; otherwise delete after PR creation. This gives you the same pattern you’ve been demonstrating: isolated coding tasks, GitHub token injection, CLI execution, tests, and PR submission — but with ACA Sandboxes as the scalable, stateful, microVM-style execution layer.

For your first demo, I would implement:

Plain Text
1
Task request -> create sandbox -> clone repo -> run pi -p -> run checks -> open PR -> delete sandbox
Show more lines

Then evolve to:

Plain Text
1
persistent named sandbox per repo/issue -> suspend/resume -> preview port -> snapshot for debugging
Show more lines

That gives you a very clean story: Pi provides the agentic coding loop; ACA Sandboxes provide the safe, stateful, cloud execution boundary; your harness provides identity, orchestration, evaluation, and PR governance.