# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

from charm import Route53LegoK8s
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness
from parameterized import parameterized


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(Route53LegoK8s)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def create_and_grant_plugin_config_secret(self, content: dict[str, str]):
        id = self.harness.add_user_secret(content)
        self.harness.grant_secret(id, self.harness.charm.app.name)
        return id

    def test_given_email_is_valid_when_config_changed_then_status_is_active(self):
        id = self.create_and_grant_plugin_config_secret(
            {
                "aws-access-key-id": "dummy key",
                "aws-secret-access-key": "dummy access key",
                "aws-region": "dummy region",
                "aws-hosted-zone-id": "dummy zone id",
            }
        )
        self.harness.update_config({"email": "example@email.com", "route53-plugin-secret": id})
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("0/0 certificate requests are fulfilled"),
        )

    def test_given_email_is_invalid_when_config_changed_then_status_is_blocked(self):
        id = self.create_and_grant_plugin_config_secret(
            {
                "aws-access-key-id": "dummy key",
                "aws-secret-access-key": "dummy access key",
                "aws-region": "dummy region",
                "aws-hosted-zone-id": "dummy zone id",
            }
        )
        self.harness.update_config({"email": "invalid-email", "route53-plugin-secret": id})
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, BlockedStatus("invalid email address"))

    @parameterized.expand(
        [
            (
                "AWS_ACCESS_KEY_ID",
                {
                    "aws-secret-access-key": "dummy access key",
                    "aws-region": "dummy region",
                    "aws-hosted-zone-id": "dummy zone id",
                },
            ),
            (
                "AWS_SECRET_ACCESS_KEY",
                {
                    "aws-access-key-id": "dummy key",
                    "aws-region": "dummy region",
                    "aws-hosted-zone-id": "dummy zone id",
                },
            ),
            (
                "AWS_REGION",
                {
                    "aws-access-key-id": "dummy key",
                    "aws-secret-access-key": "dummy access key",
                    "aws-hosted-zone-id": "dummy zone id",
                },
            ),
            (
                "AWS_HOSTED_ZONE_ID",
                {
                    "aws-access-key-id": "dummy key",
                    "aws-secret-access-key": "dummy access key",
                    "aws-region": "dummy region",
                },
            ),
        ]
    )
    def test_given_credentials_missing_when_config_changed_then_status_is_blocked(
        self, option, secret_content
    ):
        id = self.create_and_grant_plugin_config_secret(secret_content)
        self.harness.update_config({"email": "invalid-email", "route53-plugin-secret": id})
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(f"The following config options must be set: {option}"),
        )
