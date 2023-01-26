# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness
from parameterized import parameterized  # type: ignore[import]

from charm import Route53AcmeOperatorCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(Route53AcmeOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_email_is_valid_when_config_changed_then_status_is_active(self):
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

    def test_given_email_is_invalid_when_config_changed_then_status_is_blocked(self):
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

    @parameterized.expand(
        [
            (
                "AWS_ACCESS_KEY_ID",
                {
                    "email": "invalid-email",
                    "aws_secret_access_key": "dummy access key",
                    "aws_region": "dummy region",
                    "aws_hosted_zone_id": "dummy zone id",
                },
            ),
            (
                "AWS_SECRET_ACCESS_KEY",
                {
                    "email": "invalid-email",
                    "aws_access_key_id": "dummy key",
                    "aws_region": "dummy region",
                    "aws_hosted_zone_id": "dummy zone id",
                },
            ),
            (
                "AWS_REGION",
                {
                    "email": "invalid-email",
                    "aws_access_key_id": "dummy key",
                    "aws_secret_access_key": "dummy access key",
                    "aws_hosted_zone_id": "dummy zone id",
                },
            ),
            (
                "AWS_HOSTED_ZONE_ID",
                {
                    "email": "invalid-email",
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
        self.harness.update_config(config)
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(f"The following config options must be set: {option}"),
        )
