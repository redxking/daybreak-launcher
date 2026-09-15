"""No-model native smoke tests. Author: Angelis Pseftis.

May download the pinned official CLI. Never sends model prompts or publishes requests.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import daybreak as d


def main():
    command = d.runtime(d.private_root())
    with tempfile.TemporaryDirectory(prefix="daybreak-native-check-") as tmp:
        root = Path(tmp)
        ambient = root / "empty-profile"
        ambient.mkdir(mode=0o700)
        with patch.dict(os.environ, {"CODEX_HOME": str(ambient)}):
            d.configure_auth(root / "launcher")
        state = root / "launcher/security-state"
        state.mkdir(mode=0o700)
        home = state / "codex-home"
        home.mkdir(mode=0o700)
        auth = home / "auth.json"
        auth.write_text(json.dumps({"auth_mode": "apikey", "OPENAI_API_KEY": "synthetic-invalid-test-value"}))
        auth.chmod(0o600)
        assert not d.ensure_login(command, root, check_only=True), "Stored API credential was incorrectly accepted"
        print("PASS: launcher rejects stored API authentication")
        codex = Path(command[1]).parents[2] / "codex/bin/codex.js"
        p = subprocess.run([command[0], str(codex), "login", "--with-api-key"],
                           input="synthetic-invalid-test-value\n", text=True, capture_output=True, env=d.security_env())
        assert p.returncode != 0 and "API key login is disabled" in p.stdout + p.stderr, p.stderr
        print("PASS: bundled native runtime rejects API-key sign-in under forced ChatGPT configuration")
        auth.unlink(missing_ok=True)
        for route, kind in d.CLI_ROUTES.items():
            schema = json.loads(d.run(command + route.split() + ["--schema", "--format", "json"],
                                      capture=True, env=d.security_env()).stdout)
            options = schema.get("options", {}).get("properties", {})
            if kind == "model":
                assert "auth" in options and ("model" in options or "codex" in options), route
        print("PASS: enabled command routes match installed native schemas and model/auth selectors")
        assert d.official_command(command, ["scans", "list", "--format", "json"], root) == 0
        assert d.official_command(command, ["scans", "resume", "--help"], root) == 0
        print("PASS: advanced history and resume help execute without login or model use")
        repo = root / "source with spaces"
        repo.mkdir()
        d.git("init", "-b", "main", str(repo))
        (repo / "example.py").write_text('print("native smoke fixture")\n')
        d.git("add", "example.py", cwd=repo)
        d.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Fixture", cwd=repo)
        result = d.json_command(command + d.scan_args(repo, root / "results", dry_run=True), root / "dry-run.json", cwd=root)
        assert result, "No preflight output"
        print("PASS: official scan input validation with spaced repository path and no model call")
        synthetic = d.json_command(command + d.scan_args(repo, root / "mock-results", scan_only=True) + ["--mock"],
                                   root / "mock.json", cwd=root)
        assert synthetic["manifest"]["scan"]["extensions"]["mock"] is True
        try:
            d.confirmed_findings(synthetic)
        except d.SetupError:
            print("PASS: real official synthetic output is recognized and rejected for publication")
        else:
            raise AssertionError("Synthetic scan was accepted for publication")
    print("Native smoke checks passed. No security analysis, patch, API model request, or PR was performed.")


if __name__ == "__main__":
    main()
