#!/usr/bin/env python3
"""C2 contract checks against isolated files and a real port-0 HTTP server."""
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
import signal
import re
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

# Set all discovery/store roots before importing any dashboard module.
TEMP = tempfile.TemporaryDirectory(prefix="boardagents-suite-")
# Resolved: the server derives the repo from getcwd(), which reports the real path.
# On macOS the tempdir is under /var, a symlink to /private/var.
BASE = Path(TEMP.name).resolve()
os.environ["HOME"] = str(BASE / "home")
os.environ["AGENTMUX_HOME"] = str(BASE / "home/.agentmux")
os.environ.pop("CC_ENFORCE", None)
os.environ.pop("TM_ENFORCE", None)
REPO = BASE / "repo"
REPO.mkdir()
OLD_CWD = Path.cwd()
os.chdir(REPO)
sys.path.insert(0, str(Path(__file__).resolve().parent))

import server  # noqa: E402


class AgentsHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def setUp(self):
        self.dirs = [REPO / ".agentmux/agents",
                     Path(os.environ["AGENTMUX_HOME"]) / "agents",
                     REPO / ".claude/agents", Path.home() / ".claude/agents"]
        for directory in self.dirs:
            directory.mkdir(parents=True, exist_ok=True)
            for path in directory.iterdir():
                path.unlink()

    def write(self, name, scope=0, extra="", body="Persona\nwith details"):
        path = self.dirs[scope] / (name + ".md")
        path.write_text(f"---\nname: {name}\ndescription: Useful agent\ncli: codex\n"
                        f"{extra}---\n{body}", encoding="utf-8")
        return path

    def call(self, query="", method="GET", path="/api/board/agents", body=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.httpd.server_address[1]}{path}{query}",
            method=method, data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.code, json.loads(response.read())

    def save(self, body):
        return self.call(method="POST", path="/api/board/agentdef", body=body)

    def drop(self, body):
        return self.call(method="POST", path="/api/board/agentdrop", body=body)

    def definition(self, **changes):
        return dict(dict(name="writer", scope="repo", description='Useful: "writer"',
                         cli="codex", persona="Review the changes.\nBe precise.",
                         tools=["Read", "Grep"], tools_deny=["Write"],
                         capabilities=["review"], max_instances=2), **changes)

    def scoped_service(self):
        from definition_service import DefinitionScope, DefinitionService
        return DefinitionService(DefinitionScope(REPO, Path.home(),
            Path(os.environ["AGENTMUX_HOME"]), "project-one"))

    def test_scoped_identity_is_not_taken_from_body(self):
        from definition_service import EditIdentity
        service = self.scoped_service()
        body = self.definition(actor="forged-user", project_id="project-one")
        for identity in (None, {"user_id": "human-one", "project_id": "project-one"},
                         EditIdentity("human-one", "other-project"),
                         EditIdentity("", "project-one")):
            with self.subTest(identity=identity):
                with self.assertRaises(server.ccboard.Invalid):
                    service.save(None, body, identity)
                self.assertFalse((self.dirs[0] / "writer.md").exists())
        # This checks trusted-composition propagation, not HTTP authentication.
        with server.ccstore.connection() as db:
            saved = service.save(db, body, EditIdentity("human-one", "project-one"))
            row = db.execute("SELECT actor,detail FROM board_history "
                             "WHERE event='agentdef' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual(row["actor"], "human-one")
            self.assertEqual(json.loads(row["detail"]),
                             {"scope": "repo", "name": "writer", "project_id": "project-one"})
            with self.assertRaises(server.ccboard.Invalid):
                service.drop(db, saved, EditIdentity("human-one", "other-project"))
            self.assertEqual(service.agents(db, {"name": ["writer"]}), saved)
            service.drop(db, dict(saved, actor="forged-user"),
                         EditIdentity("human-one", "project-one"))
            row = db.execute("SELECT actor,detail FROM board_history "
                             "WHERE event='agentdrop' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual(row["actor"], "human-one")
            self.assertEqual(json.loads(row["detail"])["project_id"], "project-one")

    def test_scoped_roots_survive_ambient_changes(self):
        from dataclasses import FrozenInstanceError
        service = self.scoped_service()
        self.write("scoped")
        other = BASE / "other-project"
        other.mkdir(exist_ok=True)
        previous = Path.cwd()
        try:
            os.chdir(other)
            with mock.patch.dict(os.environ, {"HOME": str(other), "AGENTMUX_HOME": str(other)}):
                self.assertEqual([a["name"] for a in service.agents(None, {})["agents"]],
                                 ["scoped"])
                with server.ccstore.connection() as db:
                    service.legacy_save(db, self.definition())
            self.assertTrue((self.dirs[0] / "writer.md").exists())
            self.assertFalse((other / ".agentmux/agents/writer.md").exists())
        finally:
            os.chdir(previous)
        with self.assertRaises(FrozenInstanceError):
            service.scope.project_id = "other-project"
        with self.assertRaises(FrozenInstanceError):
            service.scope = None

    def test_legacy_and_scoped_writer_share_conflict_contract(self):
        from definition_service import EditIdentity
        service = self.scoped_service()
        identity = EditIdentity("human-one", "project-one")
        with server.ccstore.connection() as db:
            original = service.save(db, self.definition(), identity)
            changed = server.boardagents.agentdef(db, dict(original, persona="Legacy edit",
                                                         actor="legacy-label"))
            with self.assertRaises(server.ccboard.Refused):
                service.save(db, dict(original, persona="Stale scoped edit"), identity)
            self.assertEqual(service.agents(db, {"name": ["writer"]}), changed)
            audit = db.execute("SELECT actor,detail FROM board_history "
                               "WHERE event='agentdef' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual(audit["actor"], "legacy-label")
            self.assertNotIn("project_id", json.loads(audit["detail"]))

    def test_substituted_fifo_and_symlink_are_not_read(self):
        from definition_service import DefinitionService
        service = self.scoped_service()
        target = self.dirs[0] / "writer.md"
        outside = self.write("outside", 1)
        outside_bytes = outside.read_bytes()
        original_target = DefinitionService._target
        def timeout(signum, frame):
            raise AssertionError("definition read blocked")
        old_handler = signal.signal(signal.SIGALRM, timeout)
        try:
            for kind in ("fifo", "symlink"):
                original = self.write("writer")
                checksum = "sha256:" + hashlib.sha256(original.read_bytes()).hexdigest()
                def substitute(instance, body):
                    path, scope = original_target(instance, body)
                    path.unlink()
                    if kind == "fifo":
                        os.mkfifo(path)
                    else:
                        path.symlink_to(outside)
                    return path, scope
                with mock.patch.object(DefinitionService, "_target", substitute), \
                     mock.patch.object(server.ccboard, "_record") as audit:
                    signal.alarm(3)
                    try:
                        with self.assertRaises(server.ccboard.Invalid):
                            service.legacy_save(None, self.definition(checksum=checksum))
                    finally:
                        signal.alarm(0)
                    audit.assert_not_called()
                self.assertEqual(outside.read_bytes(), outside_bytes)
                target.unlink()
        finally:
            signal.signal(signal.SIGALRM, old_handler)

    def test_changed_file_identity_before_save_or_delete_is_preserved(self):
        from definition_service import DefinitionService
        service = self.scoped_service()
        check = DefinitionService._assert_revision
        for operation in (service.legacy_save, service.legacy_drop):
            path = self.write("writer")
            checksum = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            def substitute(instance, target, revision):
                replacement = target.with_suffix(".replacement")
                replacement.write_bytes(b"Independent replacement")
                os.replace(replacement, target)
                check(instance, target, revision)
            with mock.patch.object(DefinitionService, "_assert_revision", substitute), \
                 mock.patch.object(server.ccboard, "_record") as audit:
                with self.assertRaises(server.ccboard.Refused):
                    operation(None, self.definition(checksum=checksum))
                audit.assert_not_called()
            self.assertEqual(path.read_bytes(), b"Independent replacement")
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_http_read_uses_scoped_definition_importer_without_exposing_source(self):
        from definition_team import DefinitionPlugin
        self.write("imported", body="Private persona in imported bytes")
        original = DefinitionPlugin.import_all
        with mock.patch.object(DefinitionPlugin, "import_all", autospec=True,
                               side_effect=original) as imported:
            status, listing = self.call()
        self.assertEqual(status, 200)
        imported.assert_called_once()
        plugin = imported.call_args.args[0]
        self.assertEqual(plugin.repo_root, REPO)
        self.assertEqual(plugin.home, Path.home())
        self.assertEqual(plugin.global_root, Path(os.environ["AGENTMUX_HOME"]))
        self.assertEqual(imported.call_args.kwargs, {"package_name": "legacy-local-markdown"})
        self.assertNotIn("Private persona", json.dumps(listing))
        self.assertNotIn("source", listing["agents"][0])
        self.assertEqual(self.call("?name=imported")[1]["persona"],
                         "Private persona in imported bytes")

    def test_component_assets_are_explicit_and_private_sources_stay_unserved(self):
        dashboard = Path(__file__).resolve().parent
        html = (dashboard / "index.html").read_text()
        assets = re.findall(r'<script src="(src/[^"]+)"', html)
        self.assertTrue(assets)
        for asset in assets:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.httpd.server_address[1]}/{asset}", timeout=10) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get_content_type(), "text/javascript")
                self.assertEqual(response.read(), (dashboard / asset).read_bytes())
        for private in ("definition_service.py", "src/components/private.js",
                        "src/components/organisms/DefinitionEditor/DefinitionEditor.test.js",
                        "src/components/organisms/ProfilePackagePreview/ProfilePackagePreview.test.js"):
            self.assertEqual(self.call(path="/" + private)[0], 404)
        self.assertEqual(self.call(path="/../taskmgmt/profile_owner.py")[0], 403)

    def test_bundled_profile_preview_is_metadata_only_and_never_a_write_route(self):
        status, result = self.call(path="/api/board/profiles")
        self.assertEqual(status, 200)
        self.assertEqual(len(result["profiles"]), 14)
        self.assertTrue(all(row["appliesTo"] == str(REPO) for row in result["profiles"]))
        self.assertTrue(all("persona" not in row and "source" not in row for row in result["profiles"]))
        self.assertTrue(all(row["permissions"]["grants"] == [] for row in result["profiles"]))
        self.assertEqual(self.call("?project=foreign", path="/api/board/profiles")[0], 400)
        self.assertEqual(self.call(method="POST", path="/api/board/profiles",
            body={"actor": "dashboard", "uid": os.getuid(), "projectRoot": str(REPO)})[0], 405)
        self.assertFalse((REPO / ".agentmux/profile-adoptions").exists())

    def test_create_update_roundtrip_and_permissions(self):
        for scope, index in (("repo", 0), ("global", 1)):
            body = self.definition(name="writer-" + scope, scope=scope)
            status, saved = self.save(body)
            self.assertEqual(status, 200, saved)
            self.assertEqual(self.call("?name=" + body["name"]), (200, saved))
            for key, value in body.items():
                self.assertEqual(saved[key], value)
            path = Path(saved["path"])
            self.assertEqual(path.parent, self.dirs[index])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(path.parent.glob("*.tmp")), [])
            status, edited = self.save(dict(saved, persona="Revised persona"))
            self.assertEqual(status, 200, edited)
            self.assertNotEqual(saved["checksum"], edited["checksum"])
            self.assertEqual(self.call("?name=" + body["name"]), (200, edited))
        self.assertEqual(self.call()[1]["count"], 2)

    def test_stale_missing_and_deleted_checksums(self):
        _, saved = self.save(self.definition())
        path = Path(saved["path"])
        path.write_bytes(path.read_bytes() + b"\nExternal edit")
        before = path.read_bytes()
        self.assertEqual(self.save(saved)[0], 409)
        self.assertEqual(self.save(self.definition())[0], 409)
        self.assertEqual(self.drop(saved)[0], 409)
        self.assertEqual(path.read_bytes(), before)
        path.unlink()
        self.assertEqual(self.save(saved)[0], 409)
        self.assertFalse(path.exists())

    def test_collisions_reserve_invalid_files_in_every_scope(self):
        for index in range(4):
            with self.subTest(scope=index):
                path = self.write("writer", index, "posture: invalid\n")
                status, payload = self.save(self.definition())
                self.assertEqual(status, 409, payload)
                self.assertIn(str(path), str(payload["missing"]))
                self.assertIn("posture: invalid", path.read_text())
                path.unlink()

    def test_reject_paths_and_read_only_scopes(self):
        for changes in ({"scope": "claude"}, {"scope": "unknown"},
                        {"name": "../outside"}, {"path": str(BASE / "outside.md")},
                        {"path": str(self.dirs[1] / "writer.md")}, {"path": None},
                        {"path": "bad\x00path"}):
            with self.subTest(changes=changes):
                body = self.definition(**changes)
                self.assertEqual(self.save(body)[0], 400)
                self.assertEqual(self.drop(body)[0], 400)
        target = self.write("writer", 2)
        before = target.read_bytes()
        link = self.dirs[0] / "writer.md"
        link.symlink_to(target)
        self.assertEqual(self.save(self.definition())[0], 400)
        self.assertEqual(self.drop(self.definition())[0], 400)
        self.assertEqual(target.read_bytes(), before)
        link.unlink()
        self.dirs[0].rmdir()
        self.dirs[0].symlink_to(self.dirs[2], target_is_directory=True)
        try:
            self.assertEqual(self.save(self.definition())[0], 400)
            self.assertEqual(self.drop(self.definition())[0], 400)
        finally:
            self.dirs[0].unlink()
            self.dirs[0].mkdir()

    def test_validation_does_not_mutate(self):
        for changes in ({"description": ""}, {"description": "line\nbreak"},
                        {"persona": "x" * 4097}, {"role": "boss"},
                        {"max_instances": True}, {"max_instances": 9},
                        {"tools": "Read"}, {"tools": ["Read,Write"]},
                        {"capabilities": ["Bad"]}, {"posture": "invalid"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.save(self.definition(**changes))[0], 400)
                self.assertFalse((self.dirs[0] / "writer.md").exists())

    def test_drop_and_unknown_name(self):
        self.assertEqual(self.drop({"name": "unknown", "scope": "repo"})[0], 404)
        for scope in ("repo", "global"):
            _, saved = self.save(self.definition(scope=scope))
            # A drop must name the bytes it is deleting, exactly as a save must.
            # agents.js already sends agent.checksum; omitting it used to delete
            # whatever the file had become since the caller last read it.
            self.assertEqual(self.drop({"name": "writer", "scope": scope})[0], 409,
                             "a drop with no checksum must be refused")
            self.assertTrue(Path(saved["path"]).exists(),
                            "the refused drop must not have deleted anything")
            self.assertEqual(self.drop({"name": "writer", "scope": scope,
                                        "checksum": saved["checksum"]})[0], 200)
            self.assertFalse(Path(saved["path"]).exists())
            self.assertEqual(self.call("?name=writer")[0], 404)

    def test_concurrent_edit_has_one_winner(self):
        _, saved = self.save(self.definition())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.save, [dict(saved, persona="First"),
                                               dict(saved, persona="Second")]))
        self.assertEqual(sorted(status for status, _ in results), [200, 409])
        winner = next(body for status, body in results if status == 200)
        self.assertEqual(self.call("?name=writer"), (200, winner))

    def test_atomic_replace_failure_preserves_original_and_cleans_temp(self):
        _, saved = self.save(self.definition())
        path = Path(saved["path"])
        before = path.read_bytes()
        with mock.patch.object(server.boardagents.os, "replace", side_effect=OSError("test")):
            with self.assertRaises(OSError):
                server.boardagents.agentdef(None, dict(saved, persona="Replacement"))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_empty_contract(self):
        self.assertEqual(self.call(), (200, {"agents": [], "scopes":
                         ["claude", "global", "repo"], "problems": [], "count": 0}))

    def test_all_scopes_exact_payload_and_detail(self):
        for index, scope in enumerate(("repo", "global", "claude", "claude")):
            name = "agent-" + str(index)
            path = self.write(name, index)
            expected = dict(name=name, scope=scope, description="Useful agent", cli="codex",
                            model=None, auth=None, posture="workspace-write", tools=[],
                            tools_deny=[], role="worker", capabilities=[], worktree="per-member",
                            max_instances=1, path=str(path), editable=scope != "claude",
                            toolIntent={"desired": [], "denied": [], "hostEnforceable": [],
                                        "hostEnforceableDenied": [], "advisory": []},
                            checksum="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest())
            status, detail = self.call("?name=" + name)
            self.assertEqual(status, 200)
            self.assertEqual(detail, dict(expected, persona="Persona\nwith details"))
            status, payload = self.call()
            self.assertEqual(status, 200)
            self.assertEqual(set(payload), {"agents", "scopes", "problems", "count"})
            self.assertEqual(payload["agents"][index], expected)
            self.assertTrue(all("persona" not in row for row in payload["agents"]))
            self.assertEqual(payload["count"], index + 1)
            self.assertEqual(payload["scopes"], ["claude", "global", "repo"])
            self.assertEqual(payload["problems"], [])

    def test_problems_survive_and_collisions_are_excluded(self):
        warned = self.write("warned", 1, "tool: Read\n")
        bad = self.write("bad", 0, "posture: invalid\n")
        first = self.write("duplicate", 0)
        second = self.write("duplicate", 2)
        status, payload = self.call()
        self.assertEqual(status, 200)
        self.assertEqual([row["name"] for row in payload["agents"]], ["warned"])
        self.assertEqual(payload["count"], 1)
        problems = payload["problems"]
        self.assertEqual(len(problems), 3)
        self.assertTrue(all(set(p) == {"path", "scope", "error"} for p in problems))
        self.assertTrue(any(p["path"] == str(warned) and p["scope"] == "global"
                            and "tool" in p["error"] for p in problems))
        self.assertTrue(any(p["path"] == str(bad) and "posture" in p["error"] for p in problems))
        self.assertTrue(any(str(first) in str(p) and str(second) in str(p) for p in problems))
        self.assertEqual(self.call("?name=duplicate")[0], 404)

    def test_collection_fields(self):
        path = self.dirs[0] / "reviewer.md"
        path.write_text("---\nname: reviewer\ndescription: Review\ncli: claude\n"
                        "tools: Read, Grep\ntools-deny: Write\ncapabilities: review, security\n"
                        "role: reviewer\nworktree: none\nposture: read-only\n---\nReview it")
        status, payload = self.call()
        self.assertEqual(status, 200)
        row = payload["agents"][0]
        self.assertEqual(row["tools"], ["Read", "Grep"])
        self.assertEqual(row["tools_deny"], ["Write"])
        self.assertEqual(row["capabilities"], ["review", "security"])
        self.assertEqual(row["toolIntent"], {"desired": ["Read", "Grep"], "denied": ["Write"],
                         "hostEnforceable": [], "hostEnforceableDenied": [],
                         "advisory": ["Read", "Grep", "Write"]})

    def test_http_errors(self):
        self.assertEqual(self.call(method="POST")[0], 405)
        self.assertEqual(self.call("?name=unknown")[0], 404)
        for query in ("?name=", "?name=Bad", "?name=../secret", "?name=a.b",
                      "?name=a%00", "?name=a%0A", "?name=" + "a" * 65,
                      "?name=" + "a" * 300, "?name=a&name=b"):
            with self.subTest(query=query):
                status, payload = self.call(query)
                self.assertEqual(status, 400)
                self.assertIn("error", payload)
        self.assertIn(self.call(path="/api/board/nosuchop")[0], (404, 405))


if __name__ == "__main__":
    try:
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(AgentsHTTP))
    finally:
        os.chdir(OLD_CWD)
        TEMP.cleanup()
    failed = len(result.failures) + len(result.errors)
    print(f"passed {result.testsRun - failed}, failed {failed}")
    sys.exit(bool(failed))
