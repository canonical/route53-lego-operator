# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

from ops import testing
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import Route53LegoOperatorCharm

testing.SIMULATE_CAN_CONNECT = True


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(Route53LegoOperatorCharm)
        self.harness.set_leader(True)
        self.harness.set_can_connect("lego", True)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.r_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(self.r_id, "remote/0")

    def test_given_config_changed_when_email_is_valid_then_status_is_active(self):
        self.harness.update_config(
            {
                "email": "example@email.com",
                "aws_access_key_id": "dummy key",
                "aws_secret_access_key": "dummy access key",
                "aws_region": "dummy region",
                "aws_hosted_zone_id": "dummy zone id",
            }
        )
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    def test_given_config_changed_when_email_is_invalid_then_status_is_blocked(self):
        self.harness.update_config(
            {
                "email": "invalid-email",
                "aws_access_key_id": "dummy key",
                "aws_secret_access_key": "dummy access key",
                "aws_region": "dummy region",
                "aws_hosted_zone_id": "dummy zone id",
            }
        )
        self.assertEqual(self.harness.model.unit.status, BlockedStatus("Invalid email address"))

    def test_given_config_changed_when_access_key_and_credentials_file_are_not_provided_then_status_is_blocked(
        self,
    ):
        self.harness.update_config(
            {
                "email": "example@email.com",
            }
        )
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("aws-access-key-id, aws-secret-access-key must be set."),
        )

    def test_given_config_changed_when_access_key_not_provided_but_credentials_file_is_provided_then_status_is_active(
        self,
    ):
        self.harness.update_config(
            {
                "email": "example@email.com",
                "aws_shared_credentials_file": "./aws-credentials",
                "aws_region": "dummy region",
                "aws_hosted_zone_id": "dummy zone id",
            }
        )
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())
