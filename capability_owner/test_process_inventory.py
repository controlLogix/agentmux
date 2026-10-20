"""Exercise process inventory ownership with real private files and locks."""
import copy
import os
from pathlib import Path
import stat
import tempfile
import unittest

from agentmux_contracts import ContractError

from .process_admission import _RunInventory


class ProcessInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="amux-process-inventory-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.namespace = "inventory"
        self.pin = {
            "namespace": self.namespace,
            "stream": "AMX_PROCESS_INVENTORY",
            "scope": {"organizationId": "org-one", "projectId": "project-one"},
            "executorRef": {"ownerHubId": "hub-one", "id": "executor", "revision": 1},
            "profileDigest": "sha256:" + "a" * 64,
            "retention": {"maxBytes": 1048576, "reserveBytes": 65536, "replicas": 1},
        }

    def open_inventory(self, pin=None):
        inventory = _RunInventory(
            self.root, self.namespace, copy.deepcopy(self.pin if pin is None else pin)
        )
        self.addCleanup(inventory.close)
        return inventory

    def test_active_owner_refuses_a_second_owner(self):
        original = self.open_inventory()
        original.check()

        with self.assertRaises(BlockingIOError):
            self.open_inventory()

        original.check()
        original.close()
        self.open_inventory().check()

    def test_policy_conflict_releases_constructor_ownership(self):
        original = self.open_inventory()
        original.check()
        original.close()
        changed = copy.deepcopy(self.pin)
        changed["profileDigest"] = "sha256:" + "b" * 64

        with self.assertRaisesRegex(ContractError, "^capability_outcome_conflict$"):
            self.open_inventory(changed)

        self.open_inventory().check()

    def test_replaced_lock_path_refuses_the_held_owner(self):
        inventory = self.open_inventory()
        inventory.check()
        namespace = self.root / ("process-" + self.namespace)
        lock = namespace / "owner.lock"
        before = lock.stat()
        replacement = namespace / "replacement.lock"
        descriptor = os.open(
            replacement,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        held = namespace / "held.lock"
        os.rename(lock, held)
        os.replace(replacement, lock)
        retained = held.stat()
        after = lock.stat()
        self.assertEqual((before.st_dev, before.st_ino), (retained.st_dev, retained.st_ino))
        self.assertNotEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        for info in (retained, after):
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_nlink, 1)

        with self.assertRaisesRegex(ContractError, "^capability_process_unavailable$"):
            inventory.check()

        inventory.close()
        self.open_inventory().check()

    def test_closed_owner_refuses_use_and_allows_safe_reopen(self):
        original = self.open_inventory()
        original.check()
        policy = (self.root / ("process-" + self.namespace) / "policy.json").read_bytes()
        original.close()

        with self.assertRaisesRegex(ContractError, "^capability_process_unavailable$"):
            original.check()

        reopened = self.open_inventory()
        reopened.check()
        self.assertEqual(
            (self.root / ("process-" + self.namespace) / "policy.json").read_bytes(),
            policy,
        )


if __name__ == "__main__":
    unittest.main()
