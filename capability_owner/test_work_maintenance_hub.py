"""Regression for the actual selected owner/Hub source mismatch from AMUX-674."""
import unittest

from . import test_work_source as source_support


class SelectedWorkMaintenanceTopologyTests(source_support.SelectedWorkSourceFixture,
                                           unittest.IsolatedAsyncioTestCase):
    async def test_selected_registration_refuses_a_different_actual_hub_source(self):
        # This is the corrected behavior for the original signed-registration
        # reproduction: validated enrollment cannot activate a different Hub DB.
        await source_support.SelectedWorkSourceTests.test_different_original_refuses_activation_before_registration_or_roster_effect(self)
