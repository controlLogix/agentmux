"""Actual selected checkout custody behind the native signed workspace handle."""
import hashlib
import os

from hub.store import APP_ID, MIGRATIONS
from .test_live import LiveWorkspaceCapabilityTests
from .workspace_host import WorkspaceCheckoutHost


class LiveWorkspaceCheckoutTests(LiveWorkspaceCapabilityTests):
    async def prepare_read_owner(self, admin):
        await super().prepare_read_owner(admin)
        self.workspace.close()
        self.workspace = None
        checkout = self.directory / 'checkout'
        self.checkout_store.repo_add('fixture_repo', paths=[str(checkout)])
        self.checkout_store.db.close()
        self.checkout_store = None
        self.git_executor.shutdown(wait=True)
        self.git_executor = None
        database = self.directory / 'checkout.sqlite'
        database.chmod(0o600)
        raw = b'[federation]\npeer="local"\n[repos.fixture_repo]\nremote="fixture.invalid/capability-owner"\n'
        policy = self.directory / 'workspace-policy.toml'
        policy.write_bytes(raw)
        policy.chmod(0o600)
        pins = {'database':{'path':str(database),'applicationId':APP_ID,'userVersion':len(MIGRATIONS)},
            'policy':{'path':str(policy),'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}}
        self.workspace_checkout = WorkspaceCheckoutHost(pins,
            repository={'localName':'fixture_repo','repositoryId':self.repository_id,
                'normalizedRemote':'fixture.invalid/capability-owner'},local_peer='local',
            checkout_path=str(checkout),owner_uid=os.getuid())
        await self.workspace_checkout.start()
        self.workspace = self.workspace_checkout.root

