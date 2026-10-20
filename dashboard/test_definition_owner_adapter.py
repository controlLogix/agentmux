"""Offline definition preparation and single-writer preservation checks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes
import ccboard
from definition_service import DefinitionScope, DefinitionService, _WRITE_LOCK
from definition_owner_adapter import (RetainedDefinitionRevision, prepare_retained_change,
                                      prepare_catalog_change)
from identity.test_authority import fixture
from state_owner.ledger import OwnerBinding, Snapshot, StoredRecord


class DefinitionOwnerPreparation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo, self.home = self.base / "repo", self.base / "home"
        self.repo.mkdir()
        self.service = DefinitionService(DefinitionScope(self.repo, self.home, self.home / ".agentmux", "project_one"))
        self.path = self.repo / ".agentmux/agents/worker.md"
        self.body = {"name": "worker", "scope": "repo", "description": "Review changes", "persona": "Private persona"}
        self.audit = patch("definition_service.ccboard._record").start()
        self.addCleanup(patch.stopall)

    def create(self):
        return self.service.legacy_save(None, self.body)

    def payload(self, checksum=None, action="save"):
        body = {"definitionId": "definition_one", "name": "worker", "scope": "repo", "expectedChecksum": checksum}
        if action == "save":
            body["definition"] = {"description": "Review changes", "persona": "Private persona"}
        return body

    def retained(self, checksum, version=7, deleted=False):
        return RetainedDefinitionRevision("definition_one", "worker", "repo", "project_one", version, checksum, deleted)

    def prepare(self, payload, version=0, retained=None, action="save"):
        return prepare_retained_change(self.service, "definition-" + action, payload, version, retained)

    def test_create_prepares_bytes_and_revision_without_any_write(self):
        result = self.prepare(self.payload())
        self.assertEqual(result.candidate.version, 1)
        self.assertFalse(result.candidate.deleted)
        self.assertIsNone(result.effect.source.raw)
        self.assertEqual(result.candidate.checksum, "sha256:" + hashlib.sha256(result.effect.raw).hexdigest())
        self.assertFalse(self.path.parent.exists())
        self.audit.assert_not_called()
        self.assertNotIn("Private persona", repr(result))
        self.assertNotIn("Private persona", repr(result.effect))
        with self.assertRaises(FrozenInstanceError):
            result.candidate.version = 2

    def test_existing_unmapped_file_requires_import_not_first_write(self):
        row = self.create()
        raw = self.path.read_bytes()
        self.audit.reset_mock()
        with self.assertRaises(ccboard.Refused):
            self.prepare(self.payload())
        with self.assertRaises(ccboard.Refused):
            self.prepare(self.payload(row["checksum"]))
        self.assertEqual(self.path.read_bytes(), raw)
        self.audit.assert_not_called()

    def test_repeated_bytes_still_get_next_retained_integer_version(self):
        row = self.create()
        original = self.path.read_bytes()
        result = self.prepare(self.payload(row["checksum"]), 7, self.retained(row["checksum"]))
        self.assertEqual(result.candidate.version, 8)
        self.assertEqual(result.effect.raw, original)
        self.assertEqual(result.effect.source.raw, original)
        self.assertEqual(result.candidate.checksum, row["checksum"])
        with self.assertRaises(ccboard.Refused):
            self.prepare(self.payload(row["checksum"]), 6, self.retained(row["checksum"]))

    def test_drop_prepares_tombstone_and_keeps_exact_source(self):
        row = self.create()
        original = self.path.read_bytes()
        result = self.prepare(self.payload(row["checksum"], "drop"), 7, self.retained(row["checksum"]), "drop")
        self.assertTrue(result.candidate.deleted)
        self.assertEqual(result.candidate.version, 8)
        self.assertIsNone(result.candidate.checksum)
        self.assertIsNone(result.effect.raw)
        self.assertEqual(result.effect.source.raw, original)
        self.assertEqual(self.path.read_bytes(), original)

    def test_recreation_uses_tombstone_revision_and_absent_file(self):
        row = self.create()
        self.service.legacy_drop(None, {**self.body, "checksum": row["checksum"]})
        tombstone = self.retained(None, 8, True)
        result = self.prepare(self.payload(), 8, tombstone)
        self.assertEqual(result.candidate.version, 9)
        self.assertFalse(result.candidate.deleted)
        self.assertFalse(self.path.exists())
        with self.assertRaises(ccboard.Refused):
            self.prepare(self.payload(), 0, tombstone)
        self.path.write_bytes(b"external recreation")
        with self.assertRaises(ccboard.Refused):
            self.prepare(self.payload(), 8, tombstone)

    def test_identity_name_scope_project_and_checksum_must_match(self):
        row = self.create()
        retained = self.retained(row["checksum"])
        alternatives = [replace(retained, definition_id="another_id"), replace(retained, name="another-name"),
                        replace(retained, scope="global", project_id=None), replace(retained, project_id="project_two"),
                        replace(retained, checksum="sha256:" + "0" * 64)]
        for other in alternatives:
            with self.subTest(other=other), self.assertRaises(ccboard.Refused):
                self.prepare(self.payload(row["checksum"]), 7, other)

    def test_payload_cannot_supply_actor_path_or_version(self):
        for key, value in (("actor", "admin"), ("path", str(self.path)), ("expectedVersion", 0)):
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.prepare({**self.payload(), key: value})
        self.assertFalse(self.path.exists())
        self.audit.assert_not_called()

    def test_invalid_versions_and_retained_tombstones_are_refused(self):
        for version in (-1, True, 1.0, 9007199254740991):
            with self.subTest(version=version), self.assertRaises(ccboard.Invalid):
                self.prepare(self.payload(), version)
        with self.assertRaises(ccboard.Invalid):
            self.retained("sha256:" + "0" * 64, deleted=True)
        with self.assertRaises(ccboard.Invalid):
            self.retained(None)

    def test_prepared_effect_rechecks_file_identity_before_single_writer_apply(self):
        row = self.create()
        with _WRITE_LOCK:
            prepared = self.service._preflight_locked("save", {**self.body, "checksum": row["checksum"]})
            self.path.write_bytes(b"external replacement")
            with self.assertRaises(ccboard.Refused):
                self.service._apply_locked(None, prepared, "verified-human", {})
        self.assertEqual(self.path.read_bytes(), b"external replacement")
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_replace_failure_keeps_bytes_permissions_and_no_audit(self):
        row = self.create()
        original, mode = self.path.read_bytes(), self.path.stat().st_mode
        self.audit.reset_mock()
        with patch("definition_service.os.replace", side_effect=OSError("private failure")):
            with self.assertRaises(OSError):
                self.service.legacy_save(None, {**self.body, "persona": "changed", "checksum": row["checksum"]})
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.path.stat().st_mode, mode)
        self.audit.assert_not_called()

    def test_audit_failure_does_not_pretend_file_change_rolled_back(self):
        self.audit.side_effect = OSError("audit unavailable")
        with self.assertRaises(OSError):
            self.create()
        self.assertTrue(self.path.exists())
        self.assertIn(b"Private persona", self.path.read_bytes())

    def test_legacy_concurrent_updates_still_have_one_winner(self):
        row = self.create()
        def edit(persona):
            try:
                self.service.legacy_save(None, {**self.body, "persona": persona, "checksum": row["checksum"]})
                return "saved"
            except ccboard.Refused:
                return "conflict"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(edit, ("first", "second")))
        self.assertCountEqual(results, ("saved", "conflict"))

    def catalog(self, entries=(), *, sequence=1):
        record, _ = fixture()
        scope = {"organizationId": "org-one", "projectId": "project_one", "workspaceId": None}
        binding = OwnerBinding("hub-one", "definitions", "catalog-one", "definition-catalog", canonical_bytes(scope))
        record.update(entityId=binding.entity_id, entityKind=binding.entity_kind,
                      ownerDomain=binding.owner_domain, entityVersion=1, previousRevision=0,
                      effects=[], artifacts=[], state={"schemaVersion": "1.0.0", "scope": scope,
                                                       "definitions": list(entries)})
        record["operation"]["scope"] = scope
        return binding, Snapshot((StoredRecord(canonical_bytes(record), sequence),), sequence)

    def tombstone(self, **changes):
        return {"definitionId": "definition_one", "name": "worker", "targetScope": "repo",
                "version": 7, "checksum": None, "deleted": True, "contentRef": None, **changes}

    def test_catalog_keeps_aggregate_sequence_separate_from_definition_version(self):
        binding, snapshot = self.catalog([self.tombstone()])
        result = prepare_catalog_change(self.service, snapshot, binding, "definition-save", self.payload(), 7)
        self.assertEqual((result.snapshot_sequence, result.aggregate_version), (1, 1))
        self.assertEqual(result.change.candidate.version, 8)
        self.assertFalse(self.path.exists())
        self.audit.assert_not_called()

    def test_catalog_tombstone_reserves_both_id_and_name(self):
        binding, snapshot = self.catalog([self.tombstone()])
        for changes in ({"definitionId": "another_id"}, {"name": "another-name"}):
            with self.subTest(changes=changes), self.assertRaises(ccboard.Refused):
                prepare_catalog_change(self.service, snapshot, binding, "definition-save",
                                       {**self.payload(), **changes}, 7)

    def test_catalog_rejects_duplicate_targets_and_wrong_cursor(self):
        for entry in (self.tombstone(definitionId="another_id"), self.tombstone(name="another-name")):
            binding, snapshot = self.catalog([self.tombstone(), entry])
            with self.assertRaises(ccboard.Invalid):
                prepare_catalog_change(self.service, snapshot, binding, "definition-save", self.payload(), 7)
        binding, snapshot = self.catalog()
        with self.assertRaises(ccboard.Invalid):
            prepare_catalog_change(self.service, replace(snapshot, sequence=5), binding,
                                   "definition-save", self.payload(), 0)

    def test_catalog_candidate_preserves_other_tombstones_and_checks_artifact_bytes(self):
        other = self.tombstone(definitionId="another_id", name="another-name")
        binding, snapshot = self.catalog([other])
        result = prepare_catalog_change(self.service, snapshot, binding, "definition-save", self.payload(), 0)
        ref = {"artifactId": "content-one", "ownerHubId": "hub-one",
               "storeRef": {"id": "store-one", "ownerHubId": "hub-one", "revision": 1},
               "version": "version-one", "digest": result.change.candidate.checksum,
               "bytes": len(result.change.effect.raw), "mediaType": "text/markdown"}
        state = result.candidate_state(ref)
        self.assertEqual(state["definitions"][0], other)
        self.assertEqual(state["definitions"][1]["contentRef"], ref)
        with self.assertRaises(ccboard.Invalid):
            result.candidate_state({**ref, "bytes": ref["bytes"] + 1})
        with self.assertRaises(ccboard.Invalid):
            result.candidate_state({**ref, "digest": "sha256:" + "0" * 64})
        self.assertFalse(self.path.exists())

    def test_verified_large_snapshot_preparation_reads_only_latest_record(self):
        from agentmux_contracts import strict_loads
        binding, small = self.catalog([self.tombstone()])
        record = strict_loads(small.latest.record)
        record.update(entityVersion=1000000, previousRevision=999999)
        latest = StoredRecord(canonical_bytes(record), 1000000)
        accesses = []
        class VerifiedRecords:
            def __len__(self):
                return 1000000
            def __getitem__(self, index):
                accesses.append(index)
                if index != -1:
                    raise AssertionError('preparation must not read old history')
                return latest
            def __iter__(self):
                raise AssertionError('preparation must not materialize verified history')
        snapshot = Snapshot(VerifiedRecords(), 1000000)
        result = prepare_catalog_change(self.service, snapshot, binding, 'definition-save', self.payload(), 7)
        self.assertEqual(accesses, [-1])
        self.assertEqual(result.snapshot_sequence, 1000000)
        self.assertEqual(result.change.candidate.version, 8)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
