"""Profile adoption against private native files; no provider or broker execution."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "taskmgmt"))
sys.path.insert(0, str(ROOT / "dashboard"))
import agentdefs
import definition_team
import profile_packages as packages
import profile_owner
from definition_service import DefinitionScope, DefinitionService


@unittest.skipUnless(platform.system() == "Darwin" and platform.machine() == "arm64",
                     "native macOS ARM64 private file admission")
class ProfilePackages(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="profile-packages-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.project = self.base / "project"
        self.project.mkdir(mode=0o755)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.service = DefinitionService(DefinitionScope(self.project, self.home,
                                                        self.home / ".agentmux", "project-one"))
        # Only executable snapshot admission is under test. This file is never
        # executed and is not evidence of a working provider client.
        self.client = self.base / "selected-client"
        self.client.write_bytes(b"selected client fixture\n")
        self.client.chmod(0o700)
        self.clients = {"codex": str(self.client), "claude": str(self.client), "grok": str(self.client)}
        self.catalog, self.problems = packages.catalogue()

    def selection(self, name="scan-dev", **changes):
        row = {"packageId": self.catalog[name].package_name, "name": name,
               "relationship": "independent", "parentPackage": None,
               "sourceChecksum": self.catalog[name].spec.checksum,
               "overrides": {"paths": {}, "execution": {
                   "posture": "read-only", "worktree": "none", "maxInstances": 1}}}
        row.update(changes)
        return row

    def save(self, selections=None):
        if selections is None:
            selections = [self.selection()]
        with profile_owner.admit_project(self.project) as owner:
            preview, _ = packages.preview(self.project, selections, self.clients, owner=owner)
            return self.service.adopt_profiles(owner, selections, self.clients,
                                               preview["approvalChecksum"], preview["recordChecksum"])

    def record(self):
        return self.project / ".agentmux/profile-adoptions/record.json"

    def test_all_fourteen_original_bytes_fields_and_metadata_only_preview(self):
        self.assertEqual(len(self.catalog), 14)
        self.assertFalse(self.problems)
        preview = self.service.preview_profiles()
        self.assertEqual(len(preview["profiles"]), 14)
        self.assertTrue(all(row["scope"] == "project opt-in only" for row in preview["profiles"]))
        self.assertEqual(sum(row["machinePathReviewRequired"] for row in preview["profiles"]), 13)
        output = json.dumps(preview)
        for manifest in self.catalog.values():
            original = Path(manifest.spec.path).read_bytes()
            self.assertTrue(manifest.source == original, "original profile bytes changed")
            self.assertTrue(manifest.spec.checksum == packages.digest(original))
            fields, persona = agentdefs._frontmatter(original)
            parsed = agentdefs._spec(Path(manifest.spec.path), "repo", original, fields, persona,
                                      "codex", {}, {"methods": []})
            self.assertTrue(asdict(parsed) == asdict(manifest.spec), "resolved field changed")
            self.assertNotIn(manifest.spec.persona, output)
        self.assertFalse(self.record().exists())

    def test_default_membership_and_unrelated_names_remain_separate(self):
        specs, problems = agentdefs.load_all(packages.BUNDLE_ROOT, home=self.home,
                                             global_root=self.home / ".agentmux")
        self.assertFalse(packages.NAMES & specs.keys())
        self.assertFalse(any("duplicate" in row["error"] for row in problems))
        local = self.project / ".agentmux/agents"
        local.mkdir(parents=True)
        raw = b"---\nname: scan-dev\ndescription: Unrelated local definition\ncli: codex\n---\nAn unrelated local definition.\n"
        (local / "scan-dev.md").write_bytes(raw)
        specs, problems = agentdefs.load_all(self.project, home=self.home, global_root=self.home / ".agentmux")
        self.assertFalse(problems)
        self.assertEqual(specs["scan-dev"].checksum, packages.digest(raw))
        with self.assertRaisesRegex(profile_owner.ProfileError, "profile_definition_collision"):
            self.save()
        self.assertFalse(self.record().exists())

    def test_real_native_adoption_keeps_source_and_derived_revisions(self):
        before = {name: row.source for name, row in self.catalog.items()}
        selections = [self.selection(name) for name in sorted(self.catalog)]
        result = self.save(selections)
        self.assertEqual(result["profileCount"], 14)
        record = self.record()
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record.stat().st_nlink, 1)
        self.assertEqual(record.parent.stat().st_mode & 0o777, 0o700)
        specs, problems = agentdefs.load_all(self.project, home=self.home, global_root=self.home / ".agentmux")
        self.assertFalse(problems)
        self.assertEqual(set(specs), packages.NAMES)
        manifests, problems = definition_team.DefinitionPlugin(self.project, home=self.home,
            global_root=self.home / ".agentmux").import_all(package_name="local-project")
        self.assertFalse(problems)
        for manifest in manifests:
            self.assertTrue(manifest.source == before[manifest.spec.name])
            self.assertTrue(manifest.spec.persona == self.catalog[manifest.spec.name].spec.persona)
            self.assertEqual(manifest.spec.posture, "read-only")
            self.assertEqual(manifest.membership.source_checksum, packages.digest(manifest.source))
            self.assertEqual(manifest.membership.derived_checksum, definition_team.snapshot_digest(manifest.spec))
        value = json.loads(record.read_bytes())
        self.assertTrue(all(base64.b64decode(row["source"]) == before[row["name"]] for row in value["profiles"]))
        after, _ = packages.catalogue()
        self.assertTrue(all(after[name].source == raw for name, raw in before.items()))
        listed = self.service.agents(None, {})
        self.assertTrue(all(not row["editable"] and "profileMembership" in row for row in listed["agents"]))
        self.assertTrue(all("persona" not in row for row in listed["agents"]))

    def test_stale_source_host_and_record_refuse_without_overwrite(self):
        self.save()
        original = self.record().read_bytes()
        selection = [self.selection()]
        with profile_owner.admit_project(self.project) as owner:
            preview, _ = packages.preview(self.project, selection, self.clients, owner=owner)
            self.client.write_bytes(b"changed selected executable\n")
            with self.assertRaisesRegex(profile_owner.ProfileError, "profile_approval_changed"):
                self.service.adopt_profiles(owner, selection, self.clients,
                    preview["approvalChecksum"], preview["recordChecksum"])
        self.assertTrue(self.record().read_bytes() == original)
        with profile_owner.admit_project(self.project) as owner:
            preview, _ = packages.preview(self.project, selection, self.clients, owner=owner)
            with self.assertRaisesRegex(profile_owner.ProfileError, "profile_approval_changed"):
                self.service.adopt_profiles(owner, selection, self.clients,
                    preview["approvalChecksum"], packages.digest(b"stale"))
        bad = self.selection(sourceChecksum=packages.digest(b"not this source"))
        with self.assertRaisesRegex(profile_owner.ProfileError, "profile_source_changed"):
            packages.preview(self.project, [bad], self.clients)
        self.assertTrue(self.record().read_bytes() == original)

    def test_invalid_cancel_and_package_identity_leave_record_and_sources(self):
        selections = [self.selection()]
        with profile_owner.admit_project(self.project) as owner:
            packages.preview(self.project, selections, self.clients, owner=owner)
        # A preview is a canceled adoption when no subsequent explicit command runs.
        self.assertFalse(self.record().exists())
        for changes in ({"relationship": "parent-owned", "parentPackage": None},
                        {"relationship": "independent", "parentPackage": "other.package"},
                        {"overrides": {"execution": {"posture": "unrestricted", "worktree": "none", "maxInstances": 1}}}):
            with self.assertRaises(profile_owner.ProfileError):
                self.save([self.selection(**changes)])
        self.assertFalse(self.record().exists())
        with self.assertRaises(profile_owner.ProfileError):
            self.service.adopt_profiles({"uid": os.getuid()}, selections, self.clients, "", "")
        with profile_owner.admit_project(self.project) as owner:
            pass
        with self.assertRaises(profile_owner.ProfileError):
            self.service.adopt_profiles(owner, selections, self.clients, "", "")

    def test_unsafe_private_record_symlink_fifo_hardlink_and_mode(self):
        for kind in ("symlink", "fifo", "hardlink", "mode"):
            with self.subTest(kind=kind):
                self.save()
                raw = self.record().read_bytes()
                self.record().unlink()
                if kind == "symlink":
                    self.record().symlink_to(self.client)
                elif kind == "fifo":
                    os.mkfifo(self.record(), 0o600)
                else:
                    self.record().write_bytes(raw)
                    self.record().chmod(0o644 if kind == "mode" else 0o600)
                    if kind == "hardlink":
                        os.link(self.record(), self.base / "extra-link")
                specs, problems = packages.adopted(self.project)
                self.assertFalse(specs)
                self.assertEqual(len(problems), 1)
                self.record().unlink()
                if (self.base / "extra-link").exists():
                    (self.base / "extra-link").unlink()

    def test_native_acl_rejects_private_grants_without_changing_them(self):
        self.save()
        command = subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(self.record())],
                                 capture_output=True, timeout=3)
        self.assertEqual(command.returncode, 0)
        specs, problems = packages.adopted(self.project)
        self.assertFalse(specs)
        self.assertEqual(len(problems), 1)
        self.assertEqual(self.record().stat().st_mode & 0o777, 0o600)

    def test_cli_two_processes_exact_revision_one_winner(self):
        request = self.base / "request.json"
        request.write_bytes(packages.encoded({"schemaVersion": "1.0.0", "selections": [self.selection()], "clients": self.clients}))
        request.chmod(0o600)
        command = [sys.executable, str(ROOT / "taskmgmt/profilecli.py")]
        env = dict(os.environ, HOME=str(self.home), AGENTMUX_HOME=str(self.home / ".agentmux"))
        preview = subprocess.run(command + ["preview", "--project", str(self.project), "--request", str(request)],
                                 capture_output=True, timeout=8, env=env)
        self.assertEqual(preview.returncode, 0, "private CLI preview failed")
        value = json.loads(preview.stdout)
        args = command + ["adopt", "--project", str(self.project), "--request", str(request),
                          "--approval-checksum", value["approvalChecksum"], "--record-checksum", value["recordChecksum"]]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: subprocess.run(args, capture_output=True, timeout=8, env=env), range(2)))
        self.assertEqual(sorted(row.returncode for row in results), [0, 1])
        self.assertTrue(all(b"Persona" not in row.stdout + row.stderr for row in results))
        self.assertEqual(packages.adopted(self.project)[0].keys(), {"scan-dev"})

    def test_derived_path_and_parent_identity_keep_original_snapshot(self):
        manifest = self.catalog["scan-dev"]
        old = packages.PATH_REFERENCE.search(manifest.spec.description + "\n" + manifest.spec.persona).group()
        changes = {"paths": {old: str(self.project)}, "execution": {
            "posture": "workspace-write", "worktree": "per-member", "maxInstances": 2}}
        self.save([self.selection(relationship="parent-owned", parentPackage="example.project", overrides=changes)])
        row = json.loads(self.record().read_bytes())["profiles"][0]
        self.assertTrue(base64.b64decode(row["source"]) == manifest.source)
        self.assertTrue(row["original"]["persona"] == manifest.spec.persona)
        self.assertTrue((row["derived"]["persona"], row["derived"]["description"])
                        != (manifest.spec.persona, manifest.spec.description))
        self.assertEqual(row["sourceChecksum"], manifest.spec.checksum)
        self.assertNotEqual(row["sourceChecksum"], row["derivedChecksum"])
        imported, problems = definition_team.DefinitionPlugin(self.project, home=self.home,
            global_root=self.home / ".agentmux").import_all(package_name="local-project")
        self.assertFalse(problems)
        self.assertEqual(imported[0].membership.relationship, "parent-owned")
        self.assertEqual(imported[0].membership.parent_package, "example.project")

    def test_actual_source_change_after_preview_refuses_without_touching_originals(self):
        # A private copy permits a real source rewrite without editing shipped files.
        bundle = self.base / "bundle"
        destination = bundle / ".agentmux/agents"
        destination.mkdir(parents=True)
        for name, manifest in self.catalog.items():
            (destination / (name + ".md")).write_bytes(manifest.source)
        with mock.patch.object(packages, "BUNDLE_ROOT", bundle):
            with profile_owner.admit_project(self.project) as owner:
                selections = [self.selection()]
                preview, _ = packages.preview(self.project, selections, self.clients, owner=owner)
                changed = destination / "scan-dev.md"
                changed.write_bytes(changed.read_bytes() + b"\n")
                with self.assertRaisesRegex(profile_owner.ProfileError, "profile_source_changed"):
                    self.service.adopt_profiles(owner, selections, self.clients,
                        preview["approvalChecksum"], preview["recordChecksum"])
        self.assertFalse(self.record().exists())
        self.assertTrue(all(Path(manifest.spec.path).read_bytes() == manifest.source for manifest in self.catalog.values()))

    def test_record_tampering_and_ancestor_substitution_never_become_membership(self):
        self.save()
        value = json.loads(self.record().read_bytes())
        value["profiles"][0]["derived"]["persona"] += "Changed without a derived revision"
        self.record().write_bytes(packages.encoded(value))
        specs, problems = packages.adopted(self.project)
        self.assertFalse(specs)
        self.assertTrue(problems)
        with profile_owner.admit_project(self.project) as owner:
            old = self.base / "old-project"
            self.project.rename(old)
            self.project.mkdir(mode=0o755)
            try:
                with self.assertRaisesRegex(profile_owner.ProfileError, "profile_owner_changed"):
                    profile_owner.check_owner(owner)
                self.assertFalse((self.project / ".agentmux").exists())
            finally:
                self.project.rmdir()
                old.rename(self.project)

    def test_native_cleanup_releases_filesec_after_consumed_acl_failure(self):
        # Exercise actual descriptor ACL allocation/free, then inject the failure
        # result after its backend has consumed the ACL. No raw handle is retried.
        result = subprocess.run(["/bin/chmod", "+a", "everyone deny write", str(self.client)],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        real = profile_owner.C.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        real.acl_free.argtypes = [profile_owner.C.c_void_p]
        real.filesec_free.argtypes = [profile_owner.C.c_void_p]
        real.filesec_free.restype = None
        calls = []
        def free_acl(pointer):
            calls.append("acl")
            real.acl_free(pointer)
            return -1
        def free_security(pointer):
            calls.append("filesec")
            real.filesec_free(pointer)
        class Library:
            def __getattr__(self, name):
                return {"acl_free": free_acl, "filesec_free": free_security}.get(name) or getattr(real, name)
        fd = os.open(self.client, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with mock.patch.object(profile_owner.C, "CDLL", return_value=Library()):
                with self.assertRaises(profile_owner.NativeCleanupFailure) as caught:
                    profile_owner._native(fd, True)
            self.assertEqual(calls, ["acl", "filesec"])
            self.assertEqual(str(caught.exception), "profile_acl_close_failed")
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
