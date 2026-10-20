"""Task network requests cannot replace a selected destination or scope."""
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes
from .network import HTTPSDestination, SelectedNetwork


def reference(name):return {'id':name,'ownerHubId':'hub-one','revision':1}


class SelectedNetworkTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        with patch('execution_owner.network.ssl.create_default_context'):
            self.destination=HTTPSDestination(canonical_bytes(reference('approved')),'approved.invalid',
                '127.0.0.1',443,'/task','public-roots-fixture')
        self.network=SelectedNetwork(reference('network'),(self.destination,))
        self.profile={'network':{'profileRef':reference('network'),'mode':'scoped-egress',
            'destinationRefs':[reference('approved')]}}

    async def test_only_selected_exact_destination_can_be_invoked(self):
        with patch.object(HTTPSDestination,'read',new_callable=AsyncMock,return_value={'status':'ok','bodyBase64':''}) as read:
            for request in ({'destinationRef':reference('other')},
                    {'destinationRef':{**reference('approved'),'revision':2}},
                    {'destinationRef':{**reference('approved'),'ownerHubId':'other-hub'}},
                    {'destinationRef':reference('approved'),'url':'https://other.invalid/task'},
                    {'destinationRef':reference('approved'),'headers':{'Authorization':'not-permitted'}},
                    {'destinationRef':reference('approved'),'body':'not-permitted'}, []):
                self.assertEqual(await self.network.read(request),{'status':'denied'})
            read.assert_not_awaited()
            self.assertEqual((await self.network.read({'destinationRef':reference('approved')}))['status'],'ok')
            read.assert_awaited_once()

    def test_profile_cannot_widen_or_substitute_current_network_selection(self):
        self.network.check(self.profile)
        for selected in ({'profileRef':reference('other'),'mode':'scoped-egress','destinationRefs':[reference('approved')]},
                {'profileRef':reference('network'),'mode':'none','destinationRefs':[reference('approved')]},
                {'profileRef':reference('network'),'mode':'scoped-egress','destinationRefs':[]},
                {'profileRef':reference('network'),'mode':'scoped-egress','destinationRefs':[reference('approved'),reference('other')]}):
            with self.assertRaises(ContractError):self.network.check({'network':selected})
