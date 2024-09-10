# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness
from parameterized import parameterized

from charm import Route53LegoK8s


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(Route53LegoK8s)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_email_is_valid_when_config_changed_then_status_is_active(self):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(
            {
                "email": "example@email.com",
                "aws_access_key_id": "dummy key",
                "aws_secret_access_key": "dummy access key",
                "aws_region": "dummy region",
                "aws_hosted_zone_id": "dummy zone id",
            }
        )
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("0/0 certificate requests are fulfilled"),
        )

    def test_given_email_is_invalid_when_config_changed_then_status_is_blocked(self):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(
            {
                "email": "invalid-email",
                "aws_access_key_id": "dummy key",
                "aws_secret_access_key": "dummy access key",
                "aws_region": "dummy region",
                "aws_hosted_zone_id": "dummy zone id",
            }
        )
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, BlockedStatus("Invalid email address"))

    @parameterized.expand(
        [
            (
                "AWS_ACCESS_KEY_ID",
                {
                    "email": "example@email.com",
                    "aws_secret_access_key": "dummy access key",
                    "aws_region": "dummy region",
                    "aws_hosted_zone_id": "dummy zone id",
                },
            ),
            (
                "AWS_SECRET_ACCESS_KEY",
                {
                    "email": "example@email.com",
                    "aws_access_key_id": "dummy key",
                    "aws_region": "dummy region",
                    "aws_hosted_zone_id": "dummy zone id",
                },
            ),
            (
                "AWS_REGION",
                {
                    "email": "example@email.com",
                    "aws_access_key_id": "dummy key",
                    "aws_secret_access_key": "dummy access key",
                    "aws_hosted_zone_id": "dummy zone id",
                },
            ),
            (
                "AWS_HOSTED_ZONE_ID",
                {
                    "email": "example@email.com",
                    "aws_access_key_id": "dummy key",
                    "aws_secret_access_key": "dummy access key",
                    "aws_region": "dummy region",
                },
            ),
        ]
    )
    def test_given_credentials_missing_when_config_changed_then_status_is_blocked(
        self, option, config
    ):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(config)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(f"The following config options must be set: {option}"),
        )
