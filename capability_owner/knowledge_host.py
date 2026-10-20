"""Protected custody of the existing knowledge database and federation policy."""
from agentmux_contracts import ContractError
from hub.fed.plugins.knowledge import Knowledge
from .messages_host import MessageStoreHost, SelectedMessageDomain


class KnowledgeStoreHost(MessageStoreHost):
    @staticmethod
    def _repository_descriptor(repository):
        return repository is not None and MessageStoreHost._repository_descriptor(repository)

    @staticmethod
    def _tables():
        return (*MessageStoreHost._tables()[2:],
            ('p_knowledge_items', {'id', 'rid', 'repo', 'from_peer', 'author', 'title', 'body',
                'tags', 'ref', 'source', 'trust', 'untrusted', 'withdrawn', 'at'}),
            ('p_knowledge_fts', {'title', 'body', 'tags'}))

    @staticmethod
    def check_knowledge_tables(store):
        for table, columns in KnowledgeStoreHost._tables():
            if not columns <= {row['name'] for row in store.q('PRAGMA table_info(' + table + ')')}:
                raise ContractError('selected_knowledge_store_invalid')
        # Missing or changed indexing must refuse before a write can omit the
        # original search behavior. Existing records and unknown columns remain.
        trigger = store.q1('SELECT sql FROM sqlite_master WHERE type=? AND name=?',
            ('trigger', 'p_knowledge_ai'))
        def normalized(sql):
            return ''.join(sql.lower().replace('if not exists', '').split())
        if trigger is None or normalized(trigger['sql']) != normalized(Knowledge.tables[2]):
            raise ContractError('selected_knowledge_store_invalid')
        search = store.q1('SELECT sql FROM sqlite_master WHERE type=? AND name=?',
            ('table', 'p_knowledge_fts'))
        if search is None or normalized(search['sql']) != normalized(Knowledge.tables[1]):
            raise ContractError('selected_knowledge_store_invalid')
        store.q("SELECT rowid FROM p_knowledge_fts WHERE p_knowledge_fts MATCH ? LIMIT 0", ('knowledge',))

    def _open_existing(self):
        super()._open_existing()
        self.check_knowledge_tables(self._store)


class SelectedKnowledgeDomain(SelectedMessageDomain):
    """Borrow the same checked Store executor and current repository policy."""
