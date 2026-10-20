"""Read artifacts through the selected, still-live task owner's custody."""
from agentmux_contracts import ContractError
from state_owner.artifacts import OwnerArtifacts
from state_owner.task_artifact_custody import TaskArtifactCustody
from state_owner.task_host import TaskHost
from state_owner.ledger import owner_subject
from .resources import RetainedResource


class TaskArtifactResource(RetainedResource):
    def __init__(self, task, *, selection, artifacts):
        from identity.application_service_selection import ApplicationServiceSelection
        if not isinstance(task, TaskHost) or not isinstance(selection, ApplicationServiceSelection):
            raise ContractError('capability_artifact_configuration')
        super().__init__(selection.binding('task'), task.ledger, artifacts=artifacts)
        object.__setattr__(self, '_task', task)
        object.__setattr__(self, '_selection', selection)
        object.__setattr__(self, '_authority', task.owner._authority)
        self.check_current()

    def check_current(self):
        task, artifacts = self._task, self.artifacts
        task.check_health()
        custody = task._artifact_custody
        selected = self._selection.service('task')
        pin = selected.get('artifacts')
        domain = selected['connection']['jetstreamDomain']
        prefix = '$JS.API' if domain is None else '$JS.' + domain + '.API'
        identity = self._selection.stream_identity('task')
        if (task.ledger is not self.ledger or task.ledger._binding != self.binding
                or pin is None or task.owner._authority is not self._authority
                or task.service.owner is not task.owner or task.owner._ledger is not self.ledger
                or task.service._closed or task.service._host is not task
                or self.ledger._stream != selected['ledger']['stream']
                or self.ledger._subject != owner_subject(self.binding)
                or self.ledger._identity.created != identity.created
                or self.ledger._identity.minimum_sequence < identity.minimum_sequence
                or getattr(self.ledger._js, '_prefix', None) != prefix
                or getattr(self.ledger._js, '_nc', None) is not task.service._connection
                or task.service._connection.is_connected is not True
                or type(custody) is not TaskArtifactCustody
                or custody._service is not task.service or custody._ledger is not self.ledger
                or custody._artifacts is not artifacts or type(artifacts) is not OwnerArtifacts
                or artifacts._bucket != pin['bucket'] or artifacts._ref != pin['storeRef']
                or artifacts._max_bytes != pin['maxBytes'] or artifacts._owner != self.binding.hub_id
                or getattr(artifacts._js, '_prefix', None) != prefix
                or getattr(artifacts._js, '_nc', None) is not task.service._connection
                or getattr(artifacts._store, '_js', None) is not artifacts._js
                or getattr(artifacts._store, '_name', None) != pin['bucket']):
            raise ContractError('capability_artifact_stale')

    def __repr__(self):
        return '<TaskArtifactResource private>'
