"""Registered payload admission; this does not simulate owner state transitions."""
import copy
import json
from pathlib import Path
import unittest

import test_conformance as wire


class Payloads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse only transport/key setup, never either SDK implementation.
        wire.Conformance.setUpClass.__func__(cls)
        cls.payloads = json.loads((Path(__file__).parent / 'vectors/payload-examples.json').read_text())

    def accepted(self, response):
        return wire.Conformance.accepted(self, response)

    def rejected(self, response):
        wire.Conformance.rejected(self, response)

    def envelope(self, name):
        example = self.payloads[name]
        value = copy.deepcopy(self.examples['message-envelope'])
        value.update(contractId=name, kind=example['kind'], destinationServiceId=example['destinationServiceId'],
                     payload=copy.deepcopy(example['payload']))
        claims = value['ingressAttestation']['claims']
        for field in ('operation', 'messageId', 'kind', 'contractId', 'contractMajor', 'sourceHubId', 'sourceInstanceId', 'sentAt', 'correlationId'):
            claims[field] = copy.deepcopy(value[field])
        claims['audience'] = {'hubId': value['destinationHubId'], 'serviceId': value['destinationServiceId']}
        return value

    def check_cases(self, cases, allowed=False):
        # Keep outer/inner shape bindings valid so a different failure does not mask registry checks.
        for _, value in cases:
            claims = value['ingressAttestation']['claims']
            for field in ('operation', 'messageId', 'kind', 'contractId', 'contractMajor', 'sourceHubId', 'sourceInstanceId', 'sentAt', 'correlationId'):
                claims[field] = copy.deepcopy(value[field])
            claims['audience'] = {'hubId': value['destinationHubId'], 'serviceId': value['destinationServiceId']}
        for client in self.clients:
            responses = client.many([{'op': 'validatePayload', 'envelope': e} for _, e in cases])
            for (label, _), response in zip(cases, responses):
                with self.subTest(client=client.language, case=label):
                    if allowed:
                        self.assertIs(self.accepted(response), True)
                    else:
                        self.rejected(response)

    def test_board_commands_keep_original_and_owner_phase_shapes_closed(self):
        valid=[(name,self.envelope(name)) for name in
            ('federation-board-command','federation-board-dispatch','federation-board-complete')]
        for command,fields in (('assign',{'key':'SH-1','to':'peer:alice'}),
                               ('comment',{'key':'SH-1','text':'one'}),
                               ('claim',{'key':'SH-1'}),
                               ('add',{'title':'one','from':'TM-1','labels':['scope']})):
            value=self.envelope('federation-board-command')
            value['payload']['input']={'command':command,**fields}
            valid.append(('legacy-'+command,value))
        self.check_cases(valid,allowed=True)
        invalid=[]
        for name in ('federation-board-dispatch','federation-board-complete'):
            for field in ('outcome','committedRevision','success'):
                value=self.envelope(name);value['payload'][field]=True
                invalid.append((name+':forged-'+field,value))
        for change in ({'command':'replace','value':{}},
                       {'command':'claim','repo':'untrusted'},
                       {'command':'move','key':'SH-1','status':'unknown'}):
            value=self.envelope('federation-board-command');value['payload']['input']=change
            invalid.append(('legacy-change',value))
        value=self.envelope('federation-board-complete');del value['payload']['observationId']
        invalid.append(('missing-owner-observation',value))
        self.check_cases(invalid)

    def test_every_registry_payload(self):
        registry = json.loads((wire.ROOT / 'contracts/v1/registry.json').read_text())
        self.assertEqual(set(registry['contracts']), set(self.payloads))
        self.check_cases([(name, self.envelope(name)) for name in self.payloads], allowed=True)

    def test_message_bridge_commands_and_reply_keep_closed_shapes(self):
        names = ['federation-message-' + command for command in
            ('send', 'deliver', 'approve', 'inspect', 'outcome', 'reply')]
        self.check_cases([(name, self.envelope(name)) for name in names], allowed=True)
        invalid = []
        for name in names:
            schema = json.loads((wire.ROOT / 'contracts/v1/schemas' / (name + '.schema.json')).read_text())
            for field in schema['required']:
                value = self.envelope(name)
                del value['payload'][field]
                invalid.append((name + ':missing:' + field, value))
            value = self.envelope(name)
            value['payload']['unexpectedField'] = True
            invalid.append((name + ':extra', value))
        self.check_cases(invalid)

    def test_knowledge_bridge_commands_reply_and_finding_keep_closed_shapes(self):
        names = ['federation-knowledge-' + command for command in
            ('share', 'index', 'approve', 'capture', 'withdraw', 'read', 'inspect', 'outcome', 'reply')]
        names.append('federation-message-finding')
        self.check_cases([(name, self.envelope(name)) for name in names], allowed=True)
        invalid = []
        for name in names:
            schema = json.loads((wire.ROOT / 'contracts/v1/schemas' / (name + '.schema.json')).read_text())
            for field in schema['required']:
                value = self.envelope(name)
                del value['payload'][field]
                invalid.append((name + ':missing:' + field, value))
            value = self.envelope(name)
            value['payload']['unexpectedField'] = True
            invalid.append((name + ':extra', value))
        self.check_cases(invalid)

    def test_missing_and_unknown_payload_fields(self):
        cases = []
        for name in self.payloads:
            value = self.envelope(name)
            schema = json.loads((wire.ROOT / 'contracts/v1/schemas' / (name + '.schema.json')).read_text())
            for field in schema['required']:
                invalid = copy.deepcopy(value); del invalid['payload'][field]
                cases.append((name + ':missing:' + field, invalid))
            invalid = copy.deepcopy(value); invalid['payload']['unexpectedField'] = True
            cases.append((name + ':extra', invalid))
        self.check_cases(cases)

    def test_unknown_contract_wrong_major_kind_and_service(self):
        cases = []
        for name in self.payloads:
            for field, value in [('contractId', 'not-registered'), ('contractMajor', 99),
                                 ('kind', 'event' if self.payloads[name]['kind'] != 'event' else 'command')]:
                invalid = self.envelope(name); invalid[field] = value; cases.append((name + ':' + field, invalid))
            # Replies target their signed recipient, rather than a fixed owner.
            if self.payloads[name]['kind'] != 'reply':
                invalid = self.envelope(name); invalid['destinationServiceId'] = 'wrong-service'
                cases.append((name + ':service', invalid))
        self.check_cases(cases)

    def test_payload_context_binding(self):
        cases = []
        for name in self.payloads:
            for field in ('taskId', 'attemptId', 'delegationId'):
                value = self.envelope(name)
                if field in value['payload'] and value['payload'][field] is not None:
                    value['payload'][field] = 'wrong-identity'
                    cases.append((name + ':' + field, value))
        value = self.envelope('operation-outcome'); value['payload']['operationId'] = 'wrong-operation'
        cases.append(('outcome:correlation', value))
        value = self.envelope('task-reserve'); value['operation']['delegationRef'] = None
        cases.append(('reservation:missing-delegation-context', value))
        self.check_cases(cases)

    def test_receipt_execution_and_acceptance_are_not_interchangeable(self):
        cases = []
        for name, field, status in [('delivery-receipt', 'status', 'accepted'),
                                    ('delivery-receipt', 'status', 'completion_reported'),
                                    ('execution-report', 'status', 'accepted'),
                                    ('execution-report', 'status', 'received'),
                                    ('delegation-decision', 'decision', 'received')]:
            value = self.envelope(name); value['payload'][field] = status
            cases.append((name + ':' + status, value))
        value = self.envelope('operation-outcome'); value['payload']['recordRef'] = None
        cases.append(('committed-without-record', value))
        for outcome in ('unknown', 'unavailable'):
            value = self.envelope('operation-outcome'); value['payload']['outcome'] = outcome
            cases.append((outcome + ':claims-committed-record', value))
        self.check_cases(cases)

    def test_cancellation_wide_target_and_unknown_outcome_shapes(self):
        cases = []
        value = self.envelope('cancellation-request'); value['payload']['attemptId'] = None; value['payload']['delegationId'] = None
        cases.append(('task-cancellation', value))
        for outcome in ('unknown', 'unavailable'):
            value = self.envelope('operation-outcome'); value['payload'].update(outcome=outcome, recordRef=None, reason='Fixture observation')
            cases.append((outcome, value))
        self.check_cases(cases, allowed=True)

    def test_valid_signature_does_not_bypass_payload_admission(self):
        for signer, verifier in (self.clients, list(reversed(self.clients))):
            cases = []
            valid = self.envelope('task-inspect'); cases.append(('registered-positive', valid, True))
            for name in ('operation-outcome', 'startup-status-observation'):
                cases.append((name + ':signed-recipient', self.envelope(name), True))
            unknown = self.envelope('task-inspect'); unknown['contractId'] = 'not-registered'; cases.append(('unknown-contract', unknown, False))
            confused = self.envelope('delivery-receipt'); confused['payload']['status'] = 'accepted'; cases.append(('confused-receipt', confused, False))
            canonical = signer.many([{'op': 'canonical', 'value': e['payload']} for _, e, _ in cases])
            for (_, envelope, _), digest in zip(cases, canonical):
                envelope['operation']['payloadDigest'] = self.accepted(digest)['sha256']
                claims = envelope['ingressAttestation']['claims']
                for field in ('operation', 'messageId', 'kind', 'contractId', 'contractMajor', 'sourceHubId', 'sourceInstanceId', 'sentAt', 'correlationId'):
                    claims[field] = copy.deepcopy(envelope[field])
                claims['audience'] = {'hubId': envelope['destinationHubId'], 'serviceId': envelope['destinationServiceId']}
            signatures = signer.many([{'op': 'sign', 'claims': e['ingressAttestation']['claims'], 'seedHex': self.seed} for _, e, _ in cases])
            requests = []
            for (_, envelope, _), signature in zip(cases, signatures):
                envelope['ingressAttestation']['signature'] = self.accepted(signature)
                requests.append({'op': 'verifyEnvelope', 'envelope': envelope, 'publicKeyHex': self.public,
                                 'expectedAudience': envelope['ingressAttestation']['claims']['audience'], 'now': wire.NOW})
            # Each new reply retains the same signed-recipient refusal boundary.
            for label, envelope, allowed in list(cases):
                if allowed and envelope['kind'] == 'reply':
                    requests.append({'op': 'verifyEnvelope', 'envelope': envelope,
                                     'publicKeyHex': self.public,
                                     'expectedAudience': {'hubId': envelope['destinationHubId'],
                                                          'serviceId': 'different-recipient'},
                                     'now': wire.NOW})
                    cases.append((label + ':wrong-recipient', envelope, False))
            for (label, _, allowed), response in zip(cases, verifier.many(requests)):
                with self.subTest(signer=signer.language, verifier=verifier.language, case=label):
                    if allowed:
                        self.accepted(response)
                    else:
                        self.rejected(response)


    def test_storage_result_reference_is_separate_and_absent_only_when_uncertain(self):
        original=copy.deepcopy(self.payloads['capability-storage-write-reply']['payload'])
        original['receiptRef']['revision']=7
        original['resourceRef']['revision']=99
        cases=[]
        for outcome in ('applied','conflict','rejected','uncertain'):
            value=copy.deepcopy(original)
            value['outcome']=outcome
            if outcome=='uncertain':value['resourceRef']=None
            cases.append((outcome,value,True))
        for label,field,change in (
                ('missing-result','resourceRef','missing'),
                ('null-applied','resourceRef',None),
                ('missing-receipt-revision','receipt-revision','missing'),
                ('null-receipt-revision','receipt-revision',None)):
            value=copy.deepcopy(original)
            target=value['receiptRef'] if field=='receipt-revision' else value
            key='revision' if field=='receipt-revision' else field
            if change=='missing':del target[key]
            else:target[key]=change
            cases.append((label,value,False))
        value=copy.deepcopy(original);value['outcome']='uncertain'
        cases.append(('uncertain-cannot-invent-revision',value,False))
        value=copy.deepcopy(original);value['outcome']='uncertain';del value['resourceRef']
        cases.append(('uncertain-still-requires-null-field',value,False))
        for client in self.clients:
            responses=client.many([{'op':'validate','schema':'capability-storage-write-reply','value':value}
                                   for _,value,_ in cases])
            for (label,_,allowed),response in zip(cases,responses):
                with self.subTest(client=client.language,case=label):
                    if allowed:self.assertIs(self.accepted(response),True)
                    else:self.rejected(response)


    def test_storage_recovery_result_and_legacy_nonstorage_shapes(self):
        original={'operationId':'original','payloadDigest':'sha256:'+'a'*64,
            'recordRef':{'id':'receipt','ownerHubId':'hub-one','revision':7},
            'outcome':'committed','contractId':'capability-storage-write',
            'resourceRef':{'id':'resource','ownerHubId':'hub-one','revision':99}}
        cases=[]
        for outcome in ('committed','rejected','absent'):
            value=copy.deepcopy(original);value['outcome']=outcome
            if outcome=='absent':value.update(recordRef=None,resourceRef=None)
            cases.append((outcome,value,True))
        for outcome in ('committed','absent'):
            value=copy.deepcopy(original);value.pop('contractId');value.pop('resourceRef');value['outcome']=outcome
            if outcome=='absent':value['recordRef']=None
            cases.append(('legacy-'+outcome,value,True))
        for variant in ('missing-result','null-result','absent-with-result','wrong-contract','missing-contract','missing-receipt-revision'):
            value=copy.deepcopy(original)
            if variant=='missing-result':del value['resourceRef']
            elif variant=='null-result':value['resourceRef']=None
            elif variant=='absent-with-result':value.update(outcome='absent',recordRef=None)
            elif variant=='wrong-contract':value['contractId']='capability-secret-use'
            elif variant=='missing-contract':del value['contractId']
            else:del value['recordRef']['revision']
            cases.append((variant,value,False))
        for client in self.clients:
            replies=client.many([{'op':'validate','schema':'capability-outcome-query-reply','value':value}
                                 for _,value,_ in cases])
            for (label,_,allowed),response in zip(cases,replies):
                with self.subTest(client=client.language,case=label):
                    if allowed:self.assertIs(self.accepted(response),True)
                    else:self.rejected(response)


if __name__ == '__main__':
    unittest.main()
