"""Launcher contract tests. No model calls or external publication."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import daybreak as d


class LauncherTests(unittest.TestCase):
    def test_headless_detection_and_explicit_overrides(self):
        for platform in ("darwin", "win32", "linux"):
            self.assertTrue(d.use_device_auth(environment={"SSH_CONNECTION": "remote"}, platform=platform))
        self.assertTrue(d.use_device_auth(environment={}, platform="linux"))
        self.assertFalse(d.use_device_auth(environment={"DISPLAY": ":0"}, platform="linux"))
        self.assertFalse(d.use_device_auth(environment={"WAYLAND_DISPLAY": "wayland-0"}, platform="linux"))
        self.assertFalse(d.use_device_auth(environment={}, platform="darwin"))
        self.assertTrue(d.use_device_auth(True, environment={}, platform="darwin"))
        self.assertFalse(d.use_device_auth(False, environment={"SSH_TTY": "tty"}, platform="linux"))

    def test_device_login_command_and_session_reuse(self):
        success = subprocess.CompletedProcess([], 0, "Logged in using ChatGPT", "")
        missing = subprocess.CompletedProcess([], 1, "Not logged in", "")
        with patch.object(d, "security_env", return_value={}), patch.object(d, "run", side_effect=[missing, success, success]) as run:
            self.assertTrue(d.ensure_login(["node", "cli"], Path("."), device=True))
            self.assertEqual(run.call_args_list[1].args[0], ["node", "cli", "login", "--device-auth"])
        with patch.object(d, "security_env", return_value={}), patch.object(d, "run", return_value=success) as run:
            self.assertTrue(d.ensure_login(["node", "cli"], Path("."), device=True))
            self.assertEqual(run.call_count, 1)

    def test_supported_node_versions(self):
        for value in ("v22.13.0", "22.99.1", "v24.0.0", "v26.2.3"):
            self.assertTrue(d.node_supported(value), value)
        for value in ("v20.19.0", "v22.12.0", "v23.1.0", "v25.0.0", "v28.0.0", "unknown"):
            self.assertFalse(d.node_supported(value), value)

    def test_credential_urls_and_shell_strings_rejected(self):
        for value in ("https://TOKEN@github.com/a/b", "https://github.com/a/b?token=secret",
                      "https://github.com/a/b/tree/main", "https://github.com/a/../b", "--upload-pack=evil",
                      "https://evil.example/a/b", "git@github.com:a/b;touch /tmp/evil", "file:///repo"):
            with self.assertRaises((d.SetupError, ValueError), msg=value):
                d.remote_details(value)
        self.assertEqual(d.remote_details("git@github.com:owner/repo.git"),
                         ("github.com", "owner/repo", "https://github.com/owner/repo.git"))
        self.assertEqual(d.remote_details("https://gitlab.com/group/sub/repo")[1], "group/sub/repo")

    def test_api_environment_removed_host_auth_preserved(self):
        result = d.child_env({"OPENAI_API_KEY": "secret", "CODEX_API_KEY": "secret", "openai_api_key": "secret",
                              "FIREWORKS_API_KEY": "secret", "NODE_OPTIONS": "inject", "GH_TOKEN": "host", "PATH": "path",
                              "CODEX_CLI_PATH": "untrusted", "GIT_CONFIG_COUNT": "1", "git_work_tree": "original"})
        self.assertNotIn("secret", result.values())
        self.assertNotIn("NODE_OPTIONS", result)
        self.assertNotIn("CODEX_CLI_PATH", result)
        self.assertNotIn("GIT_CONFIG_COUNT", result)
        self.assertNotIn("git_work_tree", result)
        self.assertEqual(result["GH_TOKEN"], "host")

    def test_scan_arguments_literal_and_subscription_only(self):
        args = d.scan_args(Path("/repo with spaces/$(touch X)"), Path("/results"))
        self.assertIn("/repo with spaces/$(touch X)", args)
        self.assertEqual(args[args.index("--auth") + 1], "chatgpt")
        self.assertIn(d.MODEL, args)
        self.assertNotIn("--create-pr", args)
        self.assertNotIn("--patch", args)
        self.assertIn("--dry-run", d.scan_args(Path("a"), Path("b"), dry_run=True))

    def test_auth_profile_preserves_rules_and_workspace_without_tokens(self):
        import tomllib
        with tempfile.TemporaryDirectory() as tmp:
            home, target = Path(tmp) / "ambient", Path(tmp) / "launcher"
            home.mkdir(); target.mkdir()
            (home / "config.toml").write_text('forced_chatgpt_workspace_id="workspace"\nforced_login_method="chatgpt"\n[features]\na=true\n')
            (home / "auth.json").write_text('DO NOT COPY')
            (home / "managed_config.toml").write_text('test="policy"')
            (home / "rules").mkdir()
            (home / "rules/old.rules").write_text("revoked rule")
            with patch.dict(os.environ, {"CODEX_HOME": str(home)}):
                d.configure_auth(target)
            config = tomllib.loads((target / "codex-home/config.toml").read_text())
            self.assertEqual(config["forced_login_method"], "chatgpt")
            self.assertEqual(config["forced_chatgpt_workspace_id"], "workspace")
            self.assertTrue(config["features"]["a"])
            self.assertFalse((target / "codex-home/auth.json").exists())
            self.assertTrue((target / "codex-home/managed_config.toml").exists())
            self.assertEqual(d.security_env()["CODEX_HOME"], str(target / "codex-home"))
            (home / "rules/old.rules").unlink()
            with patch.dict(os.environ, {"CODEX_HOME": str(home)}):
                d.configure_auth(target)
            self.assertFalse((target / "codex-home/rules/old.rules").exists())

    def test_auth_config_conflicts_fail_closed(self):
        for text in ('forced_login_method="api"', 'model_provider="openrouter"', '[model_providers.openai]\nbase_url="https://example.com"'):
            with tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp)
                (home / "config.toml").write_text(text)
                with patch.dict(os.environ, {"CODEX_HOME": str(home)}), self.assertRaises(d.SetupError):
                    d.configure_auth(home / "isolated")

    def test_api_or_unknown_login_does_not_pass(self):
        for output in ("Logged in using API key", "", "Not logged in"):
            with patch.object(d, "security_env", return_value={}), patch.object(d, "run", return_value=
                              subprocess.CompletedProcess([], 0, output, "")):
                self.assertFalse(d.ensure_login(["node", "cli"], Path("."), check_only=True))

    def test_patch_paths_reject_escape_and_git_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for value in ("../escape", "/absolute", ".git/config", "a/../../escape", "C:\\escape"):
                with self.assertRaises(d.SetupError):
                    d.patch_files({"files": [value]}, root)
            (root / "link").symlink_to(root.parent, target_is_directory=True)
            with self.assertRaises(d.SetupError):
                d.patch_files({"files": ["link/escape"]}, root)
            self.assertEqual(d.patch_files({"files": ["src/a.py"]}, root), ["src/a.py"])

    def test_synthetic_findings_never_published(self):
        with self.assertRaises(d.SetupError):
            d.confirmed_findings({"manifest": {"scan": {"status": "completed", "extensions": {"mock": True}}}})

    def test_pr_body_distinguishes_evidence_and_suggested_tests(self):
        body = d.pr_body({"title": "Bad path", "occurrenceId": "occ_1", "summary": "Input escapes root",
                          "locations": [{"path": "a.py", "startLine": 3}], "remediationTests": ["Reject ../"]},
                         {"verification": "Executed regression test"}, "abc")
        self.assertIn("a.py:3", body)
        self.assertIn("Suggested regression tests", body)
        self.assertIn("reported by Codex Security", body)
        self.assertIn("Reject ../", body)

    def test_real_git_isolation_and_dirty_source_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo with spaces"
            self.init_repo(root)
            details = d.source_details(str(root))
            self.assertEqual(details[0], root.resolve())
            (root / "a.py").write_text("changed")
            with self.assertRaises(d.SetupError):
                d.source_details(str(root))

    def test_inherited_git_environment_cannot_redirect_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            original, isolated = Path(tmp) / "original", Path(tmp) / "isolated"
            self.init_repo(original); self.init_repo(isolated)
            head = d.git("rev-parse", "HEAD", cwd=original)
            index = (original / ".git/index").read_bytes()
            with patch.dict(os.environ, {"GIT_DIR": str(original / ".git"), "GIT_WORK_TREE": str(original),
                                         "GIT_INDEX_FILE": str(original / ".git/index")}):
                (isolated / "a.py").write_text("fixed\n")
                d.git("add", "a.py", cwd=isolated)
                d.git("commit", "-m", "Isolated fix", cwd=isolated)
            self.assertEqual(d.git("rev-parse", "HEAD", cwd=original), head)
            self.assertEqual((original / ".git/index").read_bytes(), index)
            self.assertEqual((original / "a.py").read_text(), "original\n")

    @staticmethod
    def init_repo(root):
        root.mkdir()
        d.git("init", "-b", "main", str(root))
        d.git("config", "user.name", "Fixture", cwd=root)
        d.git("config", "user.email", "fixture@example.invalid", cwd=root)
        (root / "a.py").write_text("original\n")
        d.git("add", "a.py", cwd=root)
        d.git("commit", "-m", "Fixture", cwd=root)
        d.git("remote", "add", "origin", "https://github.com/example/repo.git", cwd=root)

    def test_two_findings_make_independent_branches_and_draft_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            job = Path(tmp); repo = job / "repository"
            self.init_repo(repo)
            base = d.git("rev-parse", "HEAD", cwd=repo)
            findings = [{"occurrenceId": f"occ_{n}", "title": f"Finding {n}", "severity": {"level": "high"}}
                        for n in (1, 2)]
            doc = {"manifest": {"scan": {"id": "scan1", "status": "completed"}},
                   "findings": {"findings": findings}, "repositoryFindings": [dict(f, confirmedInLatestScan=True, status="open") for f in findings]}
            real_run = d.run
            calls = []
            def fake_run(args, **kwargs):
                if args[0] == "gh" or args[:2] == ["git", "push"]:
                    calls.append(args)
                    return subprocess.CompletedProcess(args, 0, "https://github.com/example/repo/pull/1\n", "")
                return real_run(args, **kwargs)
            def fake_patch(command, output, **kwargs):
                ident = command[2]
                self.assertEqual((repo / "a.py").read_text(), "original\n")
                self.assertIn('model="gpt-daybreak-blue-latest"', command)
                (repo / "a.py").write_text("fixed " + ident + "\n")
                return {"patches": [{"occurrenceId": ident, "status": "verified", "files": ["a.py"], "verification": "Fixture check passed"}]}
            with patch.object(d, "run", side_effect=fake_run), patch.object(d, "json_command", side_effect=fake_patch), patch.object(d, "ensure_login", return_value=True):
                result = d.publish_findings(["cli"], doc, repo, job, job, "github.com", "https://github.com/example/repo.git", "main")
            self.assertEqual(len(result), 2)
            self.assertNotEqual(result[0]["branch"], result[1]["branch"])
            for pr in result:
                self.assertEqual(d.git("rev-parse", pr["branch"] + "^", cwd=repo), base)
            requests = [args for args in calls if args[0] == "gh"]
            self.assertEqual(len(requests), 2)
            self.assertTrue(all("--draft" in args and "--body-file" in args and "main" in args for args in requests))

    def test_unverified_or_redirected_patch_never_publishes(self):
        for scenario in ("blocked", "pushurl", "extra_staged"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                job = Path(tmp); repo = job / "repository"
                self.init_repo(repo)
                finding = {"occurrenceId": "occ_1", "title": "Finding", "severity": {"level": "high"}}
                doc = {"manifest": {"scan": {"id": "s", "status": "completed"}},
                       "findings": {"findings": [finding]}, "repositoryFindings": [dict(finding, confirmedInLatestScan=True, status="open")]}
                real_run = d.run
                def guarded_run(args, **kwargs):
                    if args[0] in ("gh", "glab") or args[:2] == ["git", "push"]:
                        self.fail("Unsafe patch reached publication")
                    return real_run(args, **kwargs)
                def fake_patch(command, output, **kwargs):
                    (repo / "a.py").write_text("changed\n")
                    if scenario == "pushurl":
                        d.git("config", "remote.origin.pushurl", "https://github.com/other/repo.git", cwd=repo)
                    if scenario == "extra_staged":
                        (repo / "unreported.txt").write_text("unrelated")
                        d.git("add", "unreported.txt", cwd=repo)
                    return {"patches": [{"occurrenceId": "occ_1", "status": "blocked" if scenario == "blocked" else "verified",
                                         "files": ["a.py"], "verification": "Fixture"}]}
                with patch.object(d, "run", side_effect=guarded_run), patch.object(d, "json_command", side_effect=fake_patch), patch.object(d, "ensure_login", return_value=True), self.assertRaises(d.SetupError):
                    d.publish_findings(["cli"], doc, repo, job, job, "github.com", "https://github.com/example/repo.git", "main")
                self.assertEqual((repo / "a.py").read_text(), "changed\n")

    def test_platform_state_directory_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for platform, expected in (("win32", base / "windows/DaybreakLauncher"),
                                       ("linux", base / "linux/DaybreakLauncher"),
                                       ("darwin", base / "Library/Application Support/DaybreakLauncher")):
                with patch.object(d.sys, "platform", platform), patch.object(d.Path, "home", return_value=base), patch.dict(
                        os.environ, {"LOCALAPPDATA": str(base / "windows"), "XDG_DATA_HOME": str(base / "linux")}):
                    self.assertEqual(d.private_root(), expected)


if __name__ == "__main__":
    unittest.main()
