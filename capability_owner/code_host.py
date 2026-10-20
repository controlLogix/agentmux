"""Checked custody of the original code-share database and current policy."""
from agentmux_contracts import ContractError
from .messages_host import MessageStoreHost, SelectedMessageDomain


class CodeStoreHost(MessageStoreHost):
    @staticmethod
    def _repository_descriptor(repository):
        return repository is not None and MessageStoreHost._repository_descriptor(repository)

    @staticmethod
    def _tables():
        return (*MessageStoreHost._tables()[2:],
            ('p_code_shares', {'id', 'rid', 'repo', 'from_peer', 'author', 'ref', 'sha', 'base',
                'files', 'stat', 'log', 'note', 'untrusted', 'fetched', 'at'}))

    @staticmethod
    def check_code_tables(store):
        for table, columns in CodeStoreHost._tables():
            if not columns <= {row['name'] for row in store.q('PRAGMA table_info(' + table + ')')}:
                raise ContractError('selected_code_store_invalid')

    def _open_existing(self):
        super()._open_existing()
        self.check_code_tables(self._store)


class SelectedCodeDomain(SelectedMessageDomain):
    """Borrow the held Store executor and current repository policy."""
