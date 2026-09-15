#!/usr/bin/env python3
"""Daybreak launcher. Author: Angelis Pseftis. Python 3.11+, standard library only."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import hashlib
import getpass
import sqlite3
from contextlib import closing
from urllib.parse import urlsplit

VERSION = "0.1.27"
MODEL = "gpt-daybreak-blue-latest"
AUTH_ROOT = None
HFS_DOTGIT_IGNORABLE = frozenset({
    0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
    0x202E, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, 0xFEFF,
})

# Pinned CLI routes: authentication behavior must be reviewed before adding routes.
CLI_ROUTES = {
    "info": "read", "export": "read", "findings": "read",
    "scans list": "read", "scans show": "read", "scans logs": "read",
    "import github": "read", "scan import": "write", "publish check": "read",
    "scan": "model", "policy": "model", "scan-components": "model",
    "patch": "model", "validate": "model", "verify-fix": "model",
    "scans resume": "saved", "scans rerun": "saved",
    "findings false-positive": "write", "publish scan": "write",
    "logout": "write", "login status": "read",
}
CLI_LIMITATIONS = {
    "bulk-scan": "No explicit authentication selector; recovery settings need separate qualification.",
    "classify-severity": "No explicit authentication selector in this CLI version.",
    "scans match / compare": "Model-assisted matching has no explicit authentication/model selectors.",
    "dedupe": "Uses other named models internally; cannot promise Daybreak-only analysis.",
    "serve": "Separate hosted service; defaults to an API embeddings endpoint.",
    "install-hook": "Future hook executions need independent authentication/model enforcement.",
    "feedback": "Sends feedback externally; use the official tool deliberately.",
    "mcp / skills / completions": "Agent and shell integration requires a separate setup workflow.",
}


def print_capabilities():
    print(f"Official CLI {VERSION}: launcher capability catalog")
    for name, kind in CLI_ROUTES.items():
        print(f"  {name}: available ({kind})")
    for name, reason in CLI_LIMITATIONS.items():
        print(f"  {name}: not enabled — {reason}")
    print("Use --cli COMMAND --help for official options. Use --device-auth before --cli for headless login.")


def cli_route(arguments):
    if not arguments or arguments == ["--help"]:
        return [], "help"
    # Only the command path is used when requesting help; discard other inputs.
    path = arguments[:2] if arguments[0] in {"scans", "import", "publish", "login"} else arguments[:1]
    if arguments[:2] in (["findings", "false-positive"], ["scan", "import"]):
        path = arguments[:2]
    if any(x in ("--help", "-h") for x in arguments):
        return [x for x in path if not x.startswith("-")], "help"
    kind = CLI_ROUTES.get(" ".join(path))
    if kind is None:
        raise SetupError("This command is not enabled in the subscription-only launcher. Run --capabilities for its status, or --cli COMMAND --help for official documentation.")
    return path, kind


def check_saved_recipe(root, identifier):
    if not re.fullmatch(r"[a-fA-F0-9-]{8,36}", identifier):
        raise SetupError("Supply a saved scan ID or unique prefix of at least eight characters.")
    db = root / "security-state/workbench.sqlite3"
    if not db.is_file():
        raise SetupError("No saved scan history exists in this launcher profile.")
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as connection:
        rows = connection.execute("SELECT id, recipe_json FROM scans WHERE id LIKE ?", (identifier + "%",)).fetchall()
    if len(rows) != 1:
        raise SetupError("Scan ID was not found or is ambiguous. Use --cli scans list.")
    recipe = json.loads(rows[0][1] or "null")
    config = recipe.get("config", {}) if isinstance(recipe, dict) else {}
    allowed = {"model", "model_reasoning_effort", "model_reasoning_summary", "approval_policy", "features", "sandbox_mode", "analytics"}
    if (not isinstance(config, dict) or config.get("model") != MODEL or set(config) - allowed
            or recipe.get("mock") or recipe.get("pluginPath") or recipe.get("provider") not in (None, "openai")):
        raise SetupError("Saved scan configuration is not a qualified Daybreak recipe. Start a new subscription-authenticated scan instead.")
    return rows[0][0]


def official_command(command, arguments, root, *, device=False):
    path, kind = cli_route(arguments)
    if kind == "help":
        return run(command + path + ["--help"], env=security_env(), check=False).returncode
    schema = json.loads(run(command + path + ["--schema", "--format", "json"],
                            capture=True, env=security_env()).stdout)
    properties = schema.get("options", {}).get("properties", {})
    # Pin credentials/model and disallow configuration or executable substitution.
    forbidden = {"auth", "provider", "model", "codex", "plugin-path", "python", "mcp", "llms", "llms-full", "schema"}
    allowed_options = {re.sub(r"(?<!^)(?=[A-Z])", "-", key).lower() for key in properties}
    allowed_options |= {"format", "filter-output", "full-output", "token-count", "token-limit", "token-offset"}
    for arg in arguments[len(path):]:
        if arg.startswith("-"):
            name = arg.split("=", 1)[0].lstrip("-")
            if arg == "--" or name in forbidden or name not in allowed_options or not arg.startswith("--"):
                raise SetupError(f"Option {arg.split('=', 1)[0]} is managed by the launcher or unsupported. Use --cli COMMAND --help.")
    extra = []
    if path == ["scans", "list"] and (len(arguments) == 2 or arguments[2].startswith("--")):
        if not any(a.split("=", 1)[0] == "--scan-root" for a in arguments):
            extra += ["--scan-root", str(root)]
    if path == ["patch"] and any(a.split("=", 1)[0] == "--resume-pr" for a in arguments[1:]):
        # Native publication resume forbids auth/model overrides and runs no patch model.
        if not (len(arguments) == 3 and arguments[1] == "--resume-pr" and not arguments[2].startswith("-")):
            raise SetupError("Use exactly --cli patch --resume-pr BRANCH to retry publication without patching again.")
        kind = "write"
    if kind == "model":
        if "auth" not in properties:
            raise SetupError("CLI authentication contract changed; refusing model execution.")
        extra += ["--auth", "chatgpt"]
        if "model" in properties:
            extra += ["--model", MODEL, "--provider", "openai"]
        elif "codex" in properties:
            extra += ["--codex", f'model="{MODEL}"']
        else:
            raise SetupError("CLI model-selection contract changed; refusing model execution.")
    if kind == "saved":
        if len(arguments) <= len(path) or arguments[len(path)].startswith("-"):
            raise SetupError("Resume/rerun requires an explicit scan ID immediately after the command.")
        arguments = list(arguments)
        arguments[len(path)] = check_saved_recipe(root, arguments[len(path)])
    if kind in {"model", "saved"}:
        ensure_login(command, root, device=device)
        print("Using ChatGPT authentication and Daybreak Blue. Advanced commands use the supplied working directory; they do not create the launcher's protective copy.", flush=True)
    return run(command + list(arguments) + extra, env=security_env(), check=False).returncode


class SetupError(RuntimeError):
    pass


def child_env(source=None):
    env = dict(os.environ if source is None else source)
    # Pair environment cleanup with explicit auth and a checked ChatGPT session.
    for key in list(env):
        if (key.upper().endswith(("API_KEY", "API_TOKEN"))
                or key.upper().startswith(("OPENAI_", "AZURE_OPENAI_", "OPENROUTER_", "FIREWORKS_"))
                or key.upper().startswith("GIT_CONFIG")
                or key.upper() in {"GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                                   "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_PREFIX", "GIT_CEILING_DIRECTORIES",
                                   "CODEX_API_KEY", "CODEX_CLI_PATH", "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME"}):
            del env[key]
    env["PYTHON"] = sys.executable
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    return env


def security_env():
    env = child_env()
    if AUTH_ROOT is None:
        raise SetupError("The subscription-only profile has not been prepared.")
    env["CODEX_HOME"] = str(AUTH_ROOT / "codex-home")
    env["CODEX_SECURITY_STATE_DIR"] = str(AUTH_ROOT / "security-state")
    return env


def configure_auth(root):
    """Preserve user configuration/rules, without copying credentials or changing their profile."""
    import tomllib
    global AUTH_ROOT
    ambient = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    config_file = ambient / "config.toml"
    raw = config_file.read_text(encoding="utf-8") if config_file.exists() else ""
    config = tomllib.loads(raw)
    if config.get("forced_login_method") not in (None, "chatgpt"):
        raise SetupError("Your Codex configuration requires API authentication. This subscription-only launcher cannot use that setting.")
    if "openai" in config.get("model_providers", {}):
        raise SetupError("Your configuration overrides the OpenAI provider. Use an administrator-approved standard ChatGPT configuration for this launcher.")
    if config.get("model_provider", "openai") != "openai" or config.get("profile"):
        raise SetupError("Your configuration selects a custom provider/profile. This launcher requires the standard ChatGPT/OpenAI configuration.")
    # Preserve root/table contents; insert the restriction before the first TOML table.
    before, marker, after = raw.partition("\n[")
    if raw.startswith("["):
        before, marker, after = "", "\n", raw
    before = re.sub(r'(?m)^\s*forced_login_method\s*=.*$', "", before)
    home = root / "codex-home"
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    (home / "config.toml").write_text('forced_login_method = "chatgpt"\n' + before + marker + after, encoding="utf-8")
    # Legacy managed policy and user rules stay effective in this profile.
    for name in ("managed_config.toml", "requirements.toml", "AGENTS.md", "AGENTS.override.md"):
        src, dst = ambient / name, home / name
        if src.is_file():
            shutil.copyfile(src, dst)
        elif dst.is_file():
            dst.unlink()
    rules = ambient / "rules"
    copied_rules = home / "rules"
    if copied_rules.is_symlink():
        copied_rules.unlink()
    elif copied_rules.exists():
        shutil.rmtree(copied_rules)
    if rules.is_dir():
        shutil.copytree(rules, copied_rules)
    AUTH_ROOT = root


def run(args, *, capture=False, check=True, cwd=None, env=None, timeout=None):
    # Never use a shell: repository names and paths remain literal arguments.
    p = subprocess.run([str(a) for a in args], cwd=cwd, env=child_env() if env is None else env,
                       text=True, stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None, timeout=timeout)
    if check and p.returncode:
        raise SetupError(f"{Path(str(args[0])).name} failed (exit {p.returncode}). "
                         + ((p.stderr or p.stdout or "").strip() if capture else "See the output above."))
    return p


def node_supported(version):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version.strip())
    return bool(m and (int(m[1]) in (24, 26) or (int(m[1]) == 22 and int(m[2]) >= 13)))


def remote_details(value):
    """Accept credential-free HTTPS or Git SSH on supported public hosts."""
    if re.fullmatch(r"git@(github\.com|gitlab\.com):[A-Za-z0-9_.\-/]+", value):
        host, path = value[4:].split(":", 1)
    else:
        u = urlsplit(value)
        if u.scheme != "https" or u.username or u.password or u.port or u.query or u.fragment:
            raise SetupError("Use a credential-free https://github.com/... or https://gitlab.com/... repository URL.")
        host, path = u.hostname, u.path.lstrip("/")
    path = path.removesuffix(".git").rstrip("/")
    parts = path.split("/")
    if host not in ("github.com", "gitlab.com") or len(parts) < 2 or any(
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", p) or p in (".", "..") for p in parts):
        raise SetupError("This launcher supports GitHub.com and GitLab.com repository URLs.")
    if host == "github.com" and len(parts) != 2:
        raise SetupError("Use the repository URL, without a branch, file, or pull-request suffix.")
    return host, path, f"https://{host}/{path}.git"


def private_root():
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    root = base / "DaybreakLauncher"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def desktop_status():
    found = []
    if sys.platform == "darwin":
        for base in (Path("/Applications"), Path.home() / "Applications"):
            for name in ("Codex.app", "ChatGPT.app"):
                if (base / name).exists():
                    found.append(str(base / name))
    elif sys.platform == "win32":
        for base in (os.environ.get("LOCALAPPDATA"), os.environ.get("PROGRAMFILES")):
            if base:
                for name in ("Codex", "ChatGPT", "Programs/Codex", "Programs/ChatGPT"):
                    if (Path(base) / name).exists():
                        found.append(str(Path(base) / name))
        ps = shutil.which("powershell.exe")
        if ps:
            p = run([ps, "-NoProfile", "-Command",
                     "Get-AppxPackage | Where-Object { $_.Name -match 'Codex|ChatGPT' } | Select-Object -ExpandProperty Name"],
                    capture=True, check=False, timeout=30)
            if p.returncode == 0:
                found.extend(p.stdout.splitlines())
    else:
        for base in (Path("/usr/share/applications"), Path.home() / ".local/share/applications"):
            if base.exists():
                found.extend(str(p) for p in base.glob("*.desktop") if any(
                    name in p.name.lower() for name in ("codex", "chatgpt")))
    print("Desktop apps: " + (", ".join(found) if found else "not detected in standard locations"))
    print("Desktop apps are optional. The CLI includes its own Codex Security plugin.")


def npm_script(node):
    # Use npm's JS entry directly, avoiding Windows .cmd argument interpretation.
    npm = shutil.which("npm")
    candidates = [Path(node).resolve().parent / "node_modules/npm/bin/npm-cli.js"]
    if npm:
        p = Path(npm).resolve()
        candidates += [p, p.parent / "node_modules/npm/bin/npm-cli.js",
                       p.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"]
    for p in candidates:
        if p.is_file() and p.name == "npm-cli.js":
            return p
    raise SetupError("npm is missing. Install Node.js 24 with npm from https://nodejs.org/en/download and rerun.")


def runtime(root):
    node = shutil.which("node")
    if not node or not node_supported(run([node, "--version"], capture=True).stdout):
        raise SetupError("Install Node.js 24 (including npm): https://nodejs.org/en/download . Then reopen the terminal and rerun.")
    directory = root / ("runtime-" + VERSION)
    entry = directory / "node_modules/@openai/codex-security/bin/codex-security.mjs"
    if not entry.exists():
        print(f"Installing official Codex Security {VERSION} in your user profile…", flush=True)
        directory.mkdir(parents=True, exist_ok=True)
        run([node, npm_script(node), "install", "--prefix", directory, "--no-audit", "--no-fund",
             "--save-exact", "@openai/codex-security@" + VERSION], cwd=root)
    command = [node, str(entry)]
    info = json.loads(run(command + ["info", "--format", "json"], capture=True, cwd=root).stdout)
    if info.get("cliVersion") != VERSION:
        raise SetupError("Unexpected CLI version. Remove the launcher runtime directory and rerun setup.")
    print(f"Official CLI: {info['cliVersion']} | bundled Security plugin: {info.get('bundledPluginVersion', 'unknown')}")
    codex = directory / "node_modules/@openai/codex/bin/codex.js"
    p = run([node, codex, "plugin", "list", "--json"], capture=True, check=False, cwd=root, timeout=45)
    try:
        installed = json.loads(p.stdout)["installed"] if p.returncode == 0 else None
    except (ValueError, KeyError):
        installed = None
    if installed is None:
        print("User plugin inventory: unavailable; check Plugins in Codex. Bundled Security plugin is available.")
    else:
        print("User plugins: " + (", ".join(f"{p.get('name', '?')} ({'enabled' if p.get('enabled') else 'disabled'})"
                                              for p in installed) or "none installed"))
    return command


def use_device_auth(requested=None, *, environment=None, platform=None):
    if requested is not None:
        return requested
    env = os.environ if environment is None else environment
    platform = sys.platform if platform is None else platform
    return bool(any(env.get(key) for key in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"))
                or (platform.startswith("linux") and not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))))


def ensure_login(command, root, *, check_only=False, device=False):
    p = run(command + ["login", "status"], capture=True, check=False, cwd=root, env=security_env())
    authenticated = p.returncode == 0 and "logged in using chatgpt" in (p.stdout + p.stderr).lower()
    if not authenticated and not check_only:
        print("Sign in to ChatGPT with your Daybreak-enabled account. No API key is requested.")
        if device:
            print("Device sign-in: open the displayed verification link on any computer or phone, and enter the code. No localhost callback is needed.", flush=True)
        else:
            print("If this machine cannot open a browser, cancel and rerun with --device-auth.", flush=True)
        run(command + ["login"] + (["--device-auth"] if device else []), cwd=root, env=security_env())
        p = run(command + ["login", "status"], capture=True, check=False, cwd=root, env=security_env())
        authenticated = p.returncode == 0 and "logged in using chatgpt" in (p.stdout + p.stderr).lower()
    print("ChatGPT sign-in: " + ("active" if authenticated else "required"))
    if not authenticated and not check_only:
        raise SetupError("ChatGPT sign-in was not established. No scan was started.")
    return authenticated


def git(*args, cwd=None, check=True):
    return run(["git", *args], capture=True, cwd=cwd, check=check).stdout.strip()


def is_git_metadata_name(name):
    """Match Git's HFS+/NTFS-equivalent spellings of a .git path component."""
    hfs_name = "".join(char for char in name if ord(char) not in HFS_DOTGIT_IGNORABLE)
    if hfs_name.lower() == ".git":
        return True
    lower = name.lower()
    if lower.startswith(".git"):
        suffix = lower[4:]
    elif lower.startswith("git~1"):
        suffix = lower[5:]
    else:
        return False
    for char in suffix:
        if char in ":\\":
            return True
        if char not in " .":
            return False
    return True


def enclosing_git_metadata(local):
    """Find Git metadata at the selected directory or one of its parents without invoking Git."""
    for directory in (local, *local.parents):
        # Probe the same named path Git uses for discovery. Listing an ancestor
        # unnecessarily requires read permission in addition to traversal.
        try:
            (directory / ".git").lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SetupError(f"Cannot safely inspect Git metadata in {directory}: {exc}") from exc
        return directory
    return None


def source_details(source, *, trust_local_git=False):
    local = Path(source).expanduser()
    if local.exists():
        if not local.is_dir():
            raise SetupError("Select a code folder, not an individual file.")
        local = local.resolve()
        if not trust_local_git:
            # Supplied Git metadata can make even read-only-looking commands execute
            # repository-configured helpers. Do not silently reinterpret a checkout
            # as a snapshot that could include ignored or uncommitted files.
            if enclosing_git_metadata(local):
                raise SetupError("The selected folder contains or is inside a Git checkout. Git metadata is not inspected automatically because its configuration can run commands. Use --trust-local-git only if you trust this checkout, or copy/export committed source without Git metadata.")
            return local, None, None, None
        probe = run(["git", "rev-parse", "--show-toplevel"], cwd=local, capture=True, check=False)
        if probe.returncode:
            if (local / ".git").exists() or (local / ".git").is_symlink() or "not a git repository" not in probe.stderr.lower():
                raise SetupError("Git could not inspect this folder. Resolve the repository error first: " + probe.stderr.strip())
            return local.resolve(), None, None, None
        root = Path(probe.stdout.strip()).resolve()
        if git("status", "--porcelain", "--untracked-files=normal", cwd=root):
            raise SetupError("The local repository has uncommitted or untracked files. Commit the intended code first; this launcher reviews an isolated copy of a committed revision.")
        remote = git("remote", "get-url", "origin", cwd=root, check=False)
        revision = git("rev-parse", "HEAD", cwd=root)
        branch = git("symbolic-ref", "--short", "HEAD", cwd=root, check=False)
        if not branch:
            raise SetupError("Check out a named branch before running the launcher.")
        return root, remote, revision, branch
    remote_details(source)
    return None, source, None, None


def snapshot_folder(source, checkout, job):
    """Copy ordinary files, without following links or including common local secrets/caches."""
    source = source.resolve()
    if job.resolve().is_relative_to(source):
        raise SetupError("The review storage is inside the selected folder. Select a narrower source folder.")
    skipped_dirs = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".codex", ".ssh", "codex-home", "security-state"}
    skipped_names = {".DS_Store", "auth.json", "id_rsa", "id_ed25519"}
    included, excluded = [], []
    checkout.mkdir()
    for parent, dirs, names in os.walk(source, followlinks=False):
        parent = Path(parent)
        for name in list(dirs):
            path = parent / name
            if name in skipped_dirs or is_git_metadata_name(name) or path.is_symlink():
                dirs.remove(name)
                excluded.append(path.relative_to(source).as_posix() + "/")
        for name in names:
            path = parent / name
            relative = path.relative_to(source)
            if (path.is_symlink() or not path.is_file() or name in skipped_names or is_git_metadata_name(name)
                    or name.endswith((".pyc", ".pyo", ".pem", ".key", ".p12", ".pfx"))
                    or (name == ".env" or name.startswith(".env.")) and name != ".env.example"):
                excluded.append(relative.as_posix())
                continue
            dest = checkout / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Open without following a final symlink where the OS supports it.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as inp, dest.open("wb") as out:
                before = os.fstat(inp.fileno())
                digest = hashlib.sha256()
                while chunk := inp.read(1024 * 1024):
                    digest.update(chunk)
                    out.write(chunk)
                after = os.fstat(inp.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise SetupError("A source file changed while copying. Rerun with a stable folder.")
            dest.chmod(before.st_mode & 0o777)
            included.append({"path": relative.as_posix(), "sha256": digest.hexdigest()})
    (job / "source-snapshot.json").write_text(json.dumps({"source": str(source), "files": included, "excluded": excluded}, indent=2) + "\n", encoding="utf-8")
    if not included:
        raise SetupError("No regular source files remain after excluding credentials, links, and dependency caches.")
    git("init", "-b", "main", str(checkout))
    hooks = job / "empty-hooks"
    hooks.mkdir()
    git("config", "core.hooksPath", str(hooks), cwd=checkout)
    for field, fallback in (("user.name", getpass.getuser()), ("user.email", getpass.getuser() + "@localhost")):
        if not git("config", "--get", field, cwd=checkout, check=False):
            git("config", field, fallback, cwd=checkout)
    # Track the complete copied snapshot, even if the supplied .gitignore excludes code.
    git("add", "--force", "--all", cwd=checkout)
    git("-c", "commit.gpgsign=false", "commit", "-m", "Local source review snapshot", cwd=checkout)
    print(f"Local folder snapshot: {len(included)} files; {len(excluded)} excluded entries. See source-snapshot.json.")


def repository_login(host, remote, root, *, device=False):
    tool = "gh" if host == "github.com" else "glab"
    if not shutil.which(tool):
        link = "https://cli.github.com/" if tool == "gh" else "https://gitlab.com/gitlab-org/cli#installation"
        raise SetupError(f"Install {tool} to authenticate and create draft requests: {link} . Then rerun.")
    if run([tool, "auth", "status", "--hostname", host], capture=True, check=False, cwd=root).returncode:
        args = [tool, "auth", "login", "--hostname", host]
        if tool == "gh":
            args += ["--git-protocol", "https", "--web"]
        run(args, cwd=root)
    if run([tool, "auth", "status", "--hostname", host], capture=True, check=False, cwd=root).returncode:
        raise SetupError(f"{tool} authentication is still required.")
    if tool == "gh":
        run([tool, "auth", "setup-git", "--hostname", host], cwd=root)
        detail = json.loads(run([tool, "repo", "view", remote, "--json", "isArchived,viewerPermission"],
                               capture=True, cwd=root).stdout)
        if detail.get("isArchived"):
            raise SetupError("This GitHub repository is archived. Unarchive it or choose a writable repository for draft PRs.")
        if detail.get("viewerPermission") not in ("ADMIN", "MAINTAIN", "WRITE"):
            raise SetupError("This account cannot push a fix branch to the repository. Choose a writable repository or use --scan-only.")


def scan_args(checkout, results, *, scan_only=False, dry_run=False, deep=False):
    args = ["scan", str(checkout), "--auth", "chatgpt", "--provider", "openai", "--model", MODEL,
            "--output-dir", str(results), "--mode", "deep" if deep else "standard", "--headless", "--format", "json"]
    if dry_run:
        args += ["--dry-run"]
    # Patching is separate: the official combined shortcut creates one PR per scan.
    return args


def json_command(command, output, *, cwd):
    with output.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=cwd, env=security_env(), text=True, stdout=stream)
    if result.returncode:
        raise SetupError(f"Official CLI exited {result.returncode}. Output retained at {output}; no automatic retry.")
    return json.loads(output.read_text(encoding="utf-8"))


def confirmed_findings(document):
    scan = document["manifest"]["scan"]
    if scan.get("extensions", {}).get("mock") or scan.get("scope", {}).get("runtimeStatus") == "mock":
        raise SetupError("Synthetic findings cannot be patched or published.")
    if scan.get("status") != "completed":
        raise SetupError("The scan did not complete. Review the retained report before patching.")
    confirmed = {f["occurrenceId"] for f in document.get("repositoryFindings", [])
                 if f.get("confirmedInLatestScan") is True and f.get("status") == "open"}
    return [f for f in document["findings"]["findings"] if f.get("occurrenceId") in confirmed
            and f.get("severity", {}).get("level") in ("critical", "high", "medium", "low")]


def patch_files(patch, checkout):
    files = patch.get("files", [])
    if not files or not isinstance(files, list):
        raise SetupError("Verified patch did not name its changed files. No request created.")
    for file in files:
        if (not isinstance(file, str) or not file or "\\" in file or Path(file).is_absolute()
                or any(p in ("..", ".git") for p in Path(file).parts)
                or not (checkout / file).resolve().is_relative_to(checkout.resolve())):
            raise SetupError("Patch returned an unsafe file path. No request created.")
    return files


def pr_body(finding, patch, revision):
    locations = "\n".join(f"- `{p.get('path', '?')}:{p.get('startLine', '?')}`" for p in finding.get("locations", []))
    tests = finding.get("remediationTests") or [
        "Add a regression test for the reported input or access path.",
        "Test rejected inputs and unaffected legitimate behavior.",
        "Run the repository's normal test suite and required CI checks."]
    return (f"## Problem\n\n{finding.get('summary', finding['title'])}\n\n{locations}\n\n"
            f"## Fix\n\n{finding.get('remediation', 'See the committed diff for the exact code change.')}\n\n"
            "The Files changed view shows the original and replacement code. This request contains one finding's patch.\n\n"
            f"## Verification reported by Codex Security\n\n{patch['verification']}\n\n"
            "## Suggested regression tests\n\n" + "\n".join(f"- {t}" for t in tests) +
            f"\n\n## Review context\n\nFinding: `{finding['occurrenceId']}`. Reviewed commit: `{revision}`. "
            "Generated with Daybreak Blue. Confirm the test evidence and required CI checks before merging. "
            "The scan report records coverage and unreviewed areas; this PR does not certify the whole application.\n")


def publish_findings(command, document, checkout, job, root, host, remote, base_branch, *, publish=True):
    findings = confirmed_findings(document)
    revision = git("rev-parse", "HEAD", cwd=checkout)
    published = []
    print(f"{len(findings)} confirmed findings selected for individual fixes" + (" and draft requests." if publish else "; patches will remain local."), flush=True)
    for index, finding in enumerate(findings, 1):
        identifier = finding["occurrenceId"]
        if not re.fullmatch(r"occ_[A-Za-z0-9_-]+", identifier):
            raise SetupError("Unexpected finding identifier; no patch started.")
        if git("status", "--porcelain", cwd=checkout):
            raise SetupError(f"Review checkout has pending changes. Inspect {checkout} before continuing.")
        git("switch", "--detach", revision, cwd=checkout)
        branch = f"codex/daybreak-{identifier[4:20]}-{uuid.uuid4().hex[:8]}"
        git("switch", "-c", branch, cwd=checkout)
        if not ensure_login(command, root, check_only=True):
            raise SetupError("ChatGPT sign-in changed. Stopping before patching.")
        print(f"Fix {index}/{len(findings)}: {finding['title']}", flush=True)
        output = job / f"patch-{identifier}.json"
        result = json_command(command + ["patch", identifier, "--scan", document["manifest"]["scan"]["id"],
                              "--auth", "chatgpt", "--codex", f'model="{MODEL}"', "--format", "json"],
                              output, cwd=checkout)
        patches = result.get("patches", [])
        if len(patches) != 1 or patches[0].get("occurrenceId") != identifier:
            raise SetupError(f"Unexpected patch response. Inspect {output}; nothing was published for this finding.")
        patch = patches[0]
        if patch.get("status") != "verified" or not patch.get("verification", "").strip():
            raise SetupError(f"Fix was not verified. Inspect {output}; nothing was published for this finding.")
        if git("rev-parse", "HEAD", cwd=checkout) != revision or git("branch", "--show-current", cwd=checkout) != branch:
            raise SetupError("The patch changed the branch or commit unexpectedly. Inspect the retained checkout.")
        if publish and (git("remote", "get-url", "--all", "origin", cwd=checkout) != remote
                        or git("remote", "get-url", "--push", "--all", "origin", cwd=checkout) != remote):
            raise SetupError("The patch changed the publication remote. No request created.")
        files = patch_files(patch, checkout)
        git("--literal-pathspecs", "add", "--", *files, cwd=checkout)
        staged = git("diff", "--cached", "--name-only", "-z", cwd=checkout).split("\0")
        staged = set(staged) - {""}
        if not staged:
            raise SetupError("No staged patch changes to publish.")
        if not staged.issubset(set(files)):
            raise SetupError("The patch staged changes outside its reported files. No request created.")
        if git("diff", "--name-only", cwd=checkout) or git("ls-files", "--others", "--exclude-standard", cwd=checkout):
            raise SetupError("The patch left changes outside its reported files. Review the checkout before publishing.")
        title = "Security: " + re.sub(r"[\r\n\x00-\x1f]", " ", finding["title"])[:180]
        body = job / f"pr-{identifier}.md"
        description = pr_body(finding, patch, revision)
        if not publish:
            description = description.replace("The Files changed view shows the original and replacement code. This request contains one finding's patch.",
                                              "The accompanying .patch file shows the original and replacement code for this finding. The original folder was not edited.")
        body.write_text(description, encoding="utf-8")
        staged_tree = git("write-tree", cwd=checkout)
        git("commit", "-m", title, cwd=checkout)
        if (git("rev-parse", "HEAD^{tree}", cwd=checkout) != staged_tree
                or git("rev-parse", "HEAD^", cwd=checkout) != revision
                or git("branch", "--show-current", cwd=checkout) != branch
                or git("status", "--porcelain", cwd=checkout)
                or (publish and git("remote", "get-url", "--push", "--all", "origin", cwd=checkout) != remote)):
            raise SetupError("Commit hooks changed the expected patch state or destination. No request created.")
        if not publish:
            diff = job / f"fix-{identifier}.patch"
            diff.write_text(git("diff", "--binary", revision, branch, cwd=checkout) + "\n", encoding="utf-8")
            published.append({"finding": identifier, "branch": branch, "patch": str(diff), "published": False})
            (job / "local-fixes.json").write_text(json.dumps(published, indent=2) + "\n", encoding="utf-8")
            print(f"Verified local patch: {diff}", flush=True)
            continue
        run(["git", "push", "--set-upstream", "origin", branch], cwd=checkout)
        if host == "github.com":
            args = ["gh", "pr", "create", "--draft", "--repo", remote, "--base", base_branch,
                    "--head", branch, "--title", title, "--body-file", body]
        else:
            # glab takes a description argument. subprocess never invokes a shell.
            args = ["glab", "mr", "create", "--draft", "--repo", remote, "--target-branch", base_branch,
                    "--source-branch", branch, "--title", title, "--description", body.read_text(encoding="utf-8"), "--yes"]
        response = run(args, capture=True, cwd=checkout).stdout.strip()
        published.append({"finding": identifier, "branch": branch, "response": response})
        (job / "requests.json").write_text(json.dumps(published, indent=2) + "\n", encoding="utf-8")
        print(response, flush=True)
    return published


def main(argv=None):
    parser = argparse.ArgumentParser(description="Set up Daybreak, review a Git repository, verify patches, and open draft requests.",
                                     allow_abbrev=False)
    parser.add_argument("repository", nargs="?", help="Local code folder, Git checkout, or GitHub/GitLab repository URL")
    parser.add_argument("--check", action="store_true", help="Check setup only; may install the CLI, but does not sign in or scan")
    parser.add_argument("--dry-run", action="store_true", help="Clone and validate inputs without model use, patches, or requests")
    parser.add_argument("--scan-only", action="store_true", help="Review without patching or creating requests")
    parser.add_argument("--deep", action="store_true", help="Use a longer, broader official deep scan")
    parser.add_argument("--trust-local-git", action="store_true",
                        help="Inspect a trusted local Git checkout before isolation; never use for supplied folders or archives")
    parser.add_argument("--capabilities", action="store_true", help="List supported official workflows and compatibility limits")
    parser.add_argument("--cli", nargs=argparse.REMAINDER, help="Run an official command with subscription safeguards; all following arguments belong to that command")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--device-auth", "--headless", dest="device_auth", action="store_true", default=None,
                      help="Use ChatGPT device sign-in; selected automatically over SSH or on Linux without a display")
    auth.add_argument("--browser-auth", dest="device_auth", action="store_false", help="Use local browser sign-in instead of automatic device detection")
    args = parser.parse_args(argv)
    if args.capabilities:
        print_capabilities()
        return 0
    if args.cli is not None and (args.repository or args.check or args.dry_run or args.scan_only or args.deep or args.trust_local_git):
        parser.error("Use --cli separately from launcher scan options; put official options after --cli.")
    device_auth = use_device_auth(args.device_auth)
    if sys.version_info < (3, 11):
        raise SetupError("This launcher requires Python 3.11 or newer: https://www.python.org/downloads/")
    print("Daybreak — setup → repository review → verified fixes → draft requests", flush=True)
    desktop_status()
    if not shutil.which("git"):
        raise SetupError("Install Git from https://git-scm.com/downloads and rerun.")
    root = private_root()
    command = runtime(root)
    configure_auth(root)
    if args.cli is not None:
        return official_command(command, args.cli, root, device=device_auth)
    logged_in = ensure_login(command, root, check_only=args.check or args.dry_run, device=device_auth)
    print("Account training/retention settings: not exposed by CLI; review your account/workspace Data Controls.")
    if args.check:
        print("Setup check finished. Model access and scan execution have not been tested.")
        return 0 if logged_in else 2
    source = args.repository or input("Repository folder or GitHub/GitLab URL: ").strip().strip('"')
    if not source:
        raise SetupError("A repository folder or URL is required.")
    if args.trust_local_git and Path(source).expanduser().exists():
        print("Trusted local Git mode: inspecting repository metadata before creating the isolated checkout.")
    local, remote, revision, branch = source_details(source, trust_local_git=args.trust_local_git)
    plain_folder = local is not None and revision is None
    fix = not args.scan_only and not args.dry_run
    publish = fix and bool(remote)
    host = None
    canonical = None
    if remote:
        host, _, canonical = remote_details(remote)
        if publish:
            repository_login(host, canonical, root, device=device_auth)
    if not remote:
        print("No remote repository: analysis and verified fixes stay local. No PR will be created.")
    job = Path(tempfile.mkdtemp(prefix="review-", dir=root))
    checkout, results = job / "repository", job / "results"
    if plain_folder:
        snapshot_folder(local, checkout, job)
    else:
        clone = ["git", "clone", "--no-hardlinks", "--recurse-submodules"]
        if local:
            clone += ["--branch", branch]
        run(clone + ["--", str(local) if local else canonical, checkout], cwd=root)
    if local and not plain_folder:
        if git("rev-parse", "HEAD", cwd=checkout) != revision or git("status", "--porcelain", cwd=local):
            raise SetupError("Source changed during preparation. Rerun after saving a stable commit.")
        if canonical:
            git("remote", "set-url", "origin", canonical, cwd=checkout)
    if fix:
        for field, prompt in (("user.name", "Git commit author name"), ("user.email", "Git commit author email")):
            if not git("config", "--get", field, cwd=checkout, check=False):
                value = input(prompt + ": ").strip()
                if not value:
                    raise SetupError("Git author name and email are required for fix commits.")
                git("config", field, value, cwd=checkout)
    base_branch = branch or git("branch", "--show-current", cwd=checkout)
    if publish:
        # Require an existing target branch and matching reviewed revision.
        remote_head = git("ls-remote", "--heads", "origin", "refs/heads/" + base_branch, cwd=checkout)
        if not remote_head or remote_head.split()[0] != git("rev-parse", "HEAD", cwd=checkout):
            raise SetupError("Push or synchronize the selected branch before automatic PRs. Its local and remote commits must match.")
    scanned_revision = git('rev-parse', 'HEAD', cwd=checkout)
    print(f"Reviewing commit {scanned_revision}")
    print(f"Checkout and results: {job}")
    print("Git clones exclude LFS binary assets. Repository analysis may execute code with your OS permissions.")
    print("Using ChatGPT subscription authentication; account limits and Daybreak access still apply.")
    print("The CLI may display API-equivalent USD estimates. These are not a billing receipt or a measure of subscription allowance.")
    output = job / "scan-output.json"
    document = json_command(command + scan_args(checkout, results, scan_only=args.scan_only, dry_run=args.dry_run, deep=args.deep),
                            output, cwd=root)
    if fix:
        if git("rev-parse", "HEAD", cwd=checkout) != scanned_revision:
            raise SetupError("The scan changed the checkout commit. Inspect the retained checkout before patching.")
        publish_findings(command, document, checkout, job, root, host, canonical, base_branch, publish=publish)
    (job / "launcher-result.json").write_text(json.dumps({
        "cli_version": VERSION, "model": MODEL, "authentication": "chatgpt", "exit_code": 0,
        "dry_run": args.dry_run, "patch_and_draft_request_requested": publish,
        "local_fixes_requested": fix and not publish, "plain_folder_snapshot": plain_folder,
        "repository": str(checkout), "results": str(results)
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Saved run location: {job}")
    if args.dry_run:
        print("Input validation passed. No model analysis, patch, or request was performed.")
    else:
        print("Check the official findings, coverage, verification results, and request URLs before accepting changes.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SetupError, OSError, ValueError, subprocess.TimeoutExpired, EOFError) as exc:
        print(f"\nNext step: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped. Existing results are retained; no automatic retry.", file=sys.stderr)
        sys.exit(130)
