"""Shared signed storage-write and recovery checks for both providers."""
from agentmux_contracts import strict_loads, validate


class StorageWriteContract:
    async def test_common_storage_write_and_reconcile_preserve_original_references(self):
        raw,inner=await self.contract_prepare('contract-first')
        receipt=await self.contract_dispatch(raw)
        validate('capability-storage-write-reply',receipt)
        self.assertEqual(receipt['outcome'],'applied')
        outcome=await self.contract_outcome(inner)
        operation=strict_loads(inner)['operation']
        self.assertEqual(outcome,{'operationId':operation['operationId'],
            'payloadDigest':operation['payloadDigest'],'contractId':'capability-storage-write',
            'recordRef':receipt['receiptRef'],'resourceRef':receipt['resourceRef'],'outcome':'committed'})
        validate('capability-outcome-query-reply',outcome)

    async def test_common_storage_replay_and_reconcile_keep_result_after_later_write(self):
        raw,inner=await self.contract_prepare('contract-first')
        first=await self.contract_dispatch(raw)
        newer,_=await self.contract_prepare('contract-second',revision=first['resourceRef']['revision'])
        second=await self.contract_dispatch(newer)
        self.assertGreater(second['resourceRef']['revision'],first['resourceRef']['revision'])
        self.assertEqual(await self.contract_dispatch(raw),first)
        recovered=await self.contract_outcome(inner)
        self.assertEqual((recovered['recordRef'],recovered['resourceRef']),
                         (first['receiptRef'],first['resourceRef']))
