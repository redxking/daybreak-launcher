---
title: Daybreak Launcher
author: Angelis Pseftis
creator: Angelis Pseftis
---

# Daybreak Launcher

Review a repository with Daybreak Blue, generate fixes, and create one draft GitHub pull request or GitLab merge request per verified finding. The launcher uses the official Codex Security CLI; it does not require the earlier browser workbench.

**Experimental preview.** [Download the launcher ZIP](https://github.com/redxking/daybreak-launcher/releases/download/v0.1.0-preview.3/Daybreak-Launcher.zip) or read the [release notes](https://github.com/redxking/daybreak-launcher/releases/tag/v0.1.0-preview.3). This is an independent launcher, not an official OpenAI product.

**Public repository disclosure:** the default workflow pushes fix branches and opens draft requests automatically. On a public repository, those changes and vulnerability explanations are public before a fix is merged. Use `--scan-only` when findings need private review or coordinated disclosure first. Draft status does not make a request private.

```mermaid
flowchart LR
    A[Check setup] --> B[Sign in to ChatGPT]
    B --> C[Copy a committed repository revision]
    C --> D[Daybreak reviews the repository]
    D --> E[Fix one confirmed finding]
    E --> F{Fix verified?}
    F -->|Yes| G[Create a draft PR with tests and code changes]
    G --> H[Repeat for the next finding]
    F -->|No| I[Keep results and explain what needs attention]
```

## Start

Extract the entire ZIP before opening a launcher. Have a Daybreak-enabled ChatGPT account and a GitHub/GitLab account with permission to push branches to the repository.

| Computer | Open |
|---|---|
| Windows | `Start Daybreak.cmd` |
| macOS | `Start Daybreak.command` |
| Linux | Run `sh "Start Daybreak.sh"` in the extracted folder |
| Remote/cloud development machine | Run the Python script in its terminal with `--device-auth` |

Enter a local code folder (including an extracted ZIP), a Git checkout, or a GitHub.com/GitLab.com repository URL. The default run performs analysis, fixes, and draft requests automatically. It never merges them. Local sessions use browser sign-in when needed. SSH sessions and Linux sessions without a display automatically use ChatGPT device sign-in: open the displayed verification link on another computer or phone and enter the code. No localhost callback is needed. Use `--device-auth` (or `--headless`) to force this flow, or `--browser-auth` to force the local browser flow. An existing valid ChatGPT session is reused.

Device sign-in still requires a person to authenticate; it is not unattended CI authentication. GitHub/GitLab sign-in is separate and follows the host CLI's instructions. If the CLI reports that device authentication is disabled for the account or workspace, enable it through the applicable account/admin settings or use local browser sign-in. The launcher does not change account policy.

**First-run prerequisites:** Python 3.11+, Node.js 24 with npm, and Git. The official engine also supports Node 22.13+ within 22.x and Node 26. For requests, install `gh` (GitHub CLI) or `glab` (GitLab CLI). Missing tools produce an installation link and a rerun instruction. The launcher automatically installs its pinned official Codex Security package in the user's profile; it does not silently install system tools or request administrator access.

- Windows: `winget install --exact --id Python.Python.3.13`; install [Node.js](https://nodejs.org/en/download), [Git](https://git-scm.com/downloads), and [GitHub CLI](https://cli.github.com/) or [GitLab CLI](https://gitlab.com/gitlab-org/cli#installation). Reopen the terminal afterward.
- macOS with Homebrew: `brew install python@3.13 node@24 git gh`. Node's installer is an alternative if `node@24` is not on PATH.
- Linux: install Python 3.11+ and Git through your distribution, then a supported Node release and the appropriate host CLI. Distribution Node versions can be too old; the launcher checks the actual version.

For example:

```sh
python3 daybreak.py https://github.com/OWNER/REPOSITORY
python3 daybreak.py "/path/to/local/repository"
python3 daybreak.py --trust-local-git "/path/to/trusted/repository"
python3 daybreak.py --check
python3 daybreak.py "/path/to/repository" --dry-run
python3 daybreak.py https://github.com/OWNER/REPOSITORY --scan-only
python3 daybreak.py https://github.com/OWNER/REPOSITORY --deep --device-auth
```

On Windows, substitute `py -3` for `python3`. iPhone/iPad cannot run this local launcher; use a supported remote development machine instead.

## More workflows

Run `python3 daybreak.py --capabilities` for the complete launcher support catalog. It does not install tools, sign in, or consume model usage. `--cli` opens the official command interface with the launcher's subscription safeguards. Everything after `--cli` belongs to the official command. Put `--device-auth` before `--cli` when needed.

```sh
python3 daybreak.py --cli --help
python3 daybreak.py --cli scans list
python3 daybreak.py --cli scans show SCAN_ID
python3 daybreak.py --cli scans logs SCAN_ID
python3 daybreak.py --device-auth --cli scans resume SCAN_ID
python3 daybreak.py --cli scans rerun SCAN_ID
python3 daybreak.py --cli export SCAN_ID --export-format sarif --output findings.sarif
python3 daybreak.py --cli patch OCCURRENCE_ID --scan SCAN_ID
python3 daybreak.py --cli verify-fix --scan SCAN_ID
python3 daybreak.py --cli scan --help
```

`scans list` includes this launcher's review directories by default. Supply a repository argument or `--scan-root` to select a different scope. Use explicit scan IDs for show/logs/export when working outside the reviewed checkout; native defaults otherwise follow the current directory. Logs may include source and command output: inspect them before sharing.

**Advanced commands operate in the current directory or on the supplied target.** They do not automatically clone, copy, or create one branch per finding. Use the original repository-argument workflow for those protections. A direct `patch --create-pr` follows the official CLI's publication behavior. `patch --resume-pr BRANCH` retries a previously prepared request without running the patch model again; run it from the original patch checkout, without additional options.

| Workflow | Launcher access |
|---|---|
| Standard/deep, paths, diffs, working-tree changes, instructions, worker limits | `--cli scan` with official options |
| Component planning and component scans | `--cli scan-components` |
| Draft repository security policy | `--cli policy` |
| Validate a reported problem; patch; verify an existing fix; assess patch risk | `--cli validate`, `patch`, `verify-fix`; patch supports `--assess-patch-risk` |
| History, reports, activity, deep resume, rerun | `--cli scans list/show/logs/resume/rerun` |
| Import GitHub alerts or existing CSV/JSON findings | `--cli import github`; `--cli scan import` |
| Findings, false-positive triage, exports | `--cli findings`, `findings false-positive`, `export` |
| Publish findings to Linear or a custom findings service | `--cli publish check/scan`; requires that destination's credentials |
| Account status/logout and installed engine metadata | `--cli login status`, `logout`, `info` |

Use `--cli COMMAND --help` for exact parameters; for example, `--cli scan-components --help`. Importing findings does not validate them. Publication sends findings to the selected destination; check the official `--dry-run` option before sending. Jira is not a native publication destination in the pinned CLI. GitHub/GitLab draft code requests use the patch workflow.

### Reusing previous work

A new `--deep` run starts a new analysis; it does not automatically extend a completed standard scan. Native `scans resume` retains an interrupted deep scan's completed workers, artifacts, and session. It requires the original checkout, unchanged reviewed source, saved session, and compatible running scan state. Do not resume a scan that is still executing. The launcher checks the saved recipe's model/configuration and active ChatGPT login; the official CLI checks resume eligibility. `scans rerun` starts another scan using the saved recipe. Neither command changes a standard scan into a deep scan.

### Capabilities with compatibility limits

The catalog includes the entire official command surface, but does not claim every route is qualified for subscription-only Daybreak execution. These commands remain disabled for execution through `--cli`; their official help is available:

- Bulk scans, severity reclassification, and model-assisted scan matching/comparison need separate authentication/model qualification because the pinned commands lack explicit selectors.
- Deduplication uses other named models internally. The hosted `serve` command defaults to an API embeddings endpoint.
- Pre-commit hooks, MCP/skill installation, and shell completions require a separate integration workflow. The CLI's MCP integration exposes metadata, not a complete scanning server.
- Feedback sends information to OpenAI and remains outside this launcher workflow.

Model/provider/authentication overrides, alternative plugins/interpreters, and unrecognized option aliases are rejected. Model commands use explicit ChatGPT authentication and Daybreak; saved-scan recovery checks the retained configuration first. This preserves the subscription-only constraint instead of offering an unrestricted CLI passthrough. Destination credentials for GitHub, GitLab, Linear, and custom services are separate from model authentication.

## What it checks and changes

- Detects desktop apps in common installation locations and lists installed/enabled Codex plugins when the CLI can report them. Detection is advisory; a portable/custom app location may be missed. Neither the desktop app nor separate Security plugin installation is required because the official CLI bundles that plugin.
- Uses a separate launcher profile and fresh ChatGPT sign-in when needed. It copies user configuration, rules, and legacy managed-policy files without copying login tokens. It preserves the forced workspace setting and rejects a configuration requiring API login or overriding the OpenAI provider. It sets `forced_login_method="chatgpt"`, strips API-key environment variables, checks ChatGPT login status, and explicitly selects ChatGPT authentication and Daybreak Blue. It does not purchase credits, reset usage, or fall back to API authentication. Subscription limits and model entitlement still apply.
- Reads each user's actual plugin state; it does not assume everyone has the same setup. Account training and retention controls are **not exposed by this CLI**. Review those in the user's account/workspace settings. The launcher does not claim to verify or change them.
- Remote Git repositories are cloned at a committed revision into a separate review directory. Ordinary local folders are handled as plain-file snapshots. A local path containing or inside a Git checkout stops before inspecting its metadata; use `--trust-local-git` only for a checkout whose Git metadata you already trust. This preserves clean named-branch and remote-aware behavior, but lets Git interpret that metadata before isolation. For PRs, the selected revision must already match the remote branch. Commit/push intended changes first. Submodules are initialized in trusted Git mode; Git LFS binary assets are excluded. This is a source review, not an all-assets inspection.
- Checks repository authentication and Git author identity. GitHub archived/read-only repositories stop before scanning in PR mode. GitLab authorization failures are reported by the host/Git commands; there is no claim that push permission was prevalidated. GitHub setup may configure its Git credential helper.
- Runs the official repository analysis, then patches confirmed findings individually with the same Daybreak model. Every patch gets a separate branch from the reviewed commit and an explicit target branch. Only a result reported as verified, with verification evidence and a consistent changed-file list, proceeds to a draft request. Failed fixes or unexpected changes stop the run and retain the checkout.
- Draft requests include the problem, affected locations, remediation, reported verification, and suggested tests. The host's Files changed view shows the exact original and replacement code. The launcher labels model-reported verification; it does not independently prove test assertions or certify application security.

The official combined `scan --patch --create-pr` command creates one PR per scan. This launcher separates patch and publication calls to meet the one-PR-per-finding requirement. Draft bodies and Git commits use the authenticated developer's configured identity; the guide's author is Angelis Pseftis.

## Local folders and untrusted Git metadata

An extracted release ZIP or ordinary local folder is supported directly; you do not need to run `git init` in it. The launcher does not inspect local Git metadata by default. If it detects the selected path is a Git checkout, it stops instead of silently including ignored or uncommitted files; either use `--trust-local-git` for metadata you trust or export/copy the committed source without `.git`. Plain folders are copied to a review directory and a Git snapshot is created only inside that copy. Common credential files, Git metadata (including HFS+/NTFS-equivalent names), symbolic links, and dependency caches are excluded. `source-snapshot.json` lists every included file with its SHA-256 hash and every excluded entry. This is a filename-based exclusion list, not a comprehensive secret detector.

The model reviews the copy and generates verified fixes on separate local branches. Each fix is saved as a `fix-occ_*.patch` file, with verification output and `local-fixes.json`. Your original folder is not edited and no remote request is created. Inspect the patch, then apply the chosen change from the original folder with `git apply /path/to/fix-occ_ID.patch`. Check first with `git apply --check /path/to/fix-occ_ID.patch`. Separate patches can overlap; rerun tests after applying them. A trusted clean Git checkout with no origin also keeps fixes locally when selected with `--trust-local-git`.

For example:

```sh
python3 daybreak.py --deep "/path/to/Daybreak Launcher"
```

## Results and limitations

The CLI displays API-equivalent cost estimates even with ChatGPT authentication. Those figures are not billing receipts or measurements of remaining subscription allowance. Token activity indicates model work; a scan still needs its final report and coverage results before completion can be claimed.

Results stay under `DaybreakLauncher` in `%LOCALAPPDATA%` (Windows), `~/Library/Application Support` (macOS), or `$XDG_DATA_HOME` / `~/.local/share` (Linux). Each run prints its folder. Read the official `report.md`, findings, coverage, patch JSON files, and `requests.json`. A zero finding count does not establish security. Test recommendations are distinct from executed test evidence.

Scans may execute repository code with the user's OS permissions. An isolated checkout protects working files from ordinary patch edits; **it is not a security sandbox**. Run untrusted projects in an appropriately isolated development environment without unrelated credentials. The launcher filters model API-key variables, not every possible secret, and host credentials are needed for publication.

No Jira integration is required to create code-host requests. Self-hosted GitHub/GitLab, uncommitted-code snapshots, unattended token-based CI, and mobile local execution are outside this small launcher's current scope. A browser/device sign-in may be required on cloud machines. One failed finding stops subsequent publication to preserve its evidence; earlier created requests remain open. Resolve the reported failure before rerunning, since a new full run can create new requests.

The CLI is pinned to **0.1.27**. Update that pin only after checking authentication and output contracts. The retained browser workbench remains a separate prototype.

## Verification

On macOS, the original scan workflow and advanced command routing have unit/integration and native CLI smoke coverage. Windows/Linux branches require native qualification before broad distribution. A dry run checks preparation, not model entitlement, scan quality, vulnerability reproduction, or actual PR publication. See the accompanying `test-results.txt` for exact completed checks and their boundaries.

To repeat the tests from the extracted folder:

```sh
python3 -m unittest test_launcher.py -v
python3 verify_native.py
```

The native smoke script may install the pinned CLI. It checks authentication refusal and preflight, then generates explicitly synthetic output to test the publication rejection. It performs no model analysis or external publication.

## Official references

- [CLI setup, sign-in, scans and patches](https://learn.chatgpt.com/docs/security/cli)
- [Security plugin and desktop workbench](https://learn.chatgpt.com/docs/security/plugin)
- [CLI FAQ](https://learn.chatgpt.com/docs/security/cli/faq)
- [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
- [Official Codex Security source](https://github.com/openai/codex-security)
