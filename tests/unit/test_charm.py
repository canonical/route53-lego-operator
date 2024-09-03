# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import pytest
from charm import Route53LegoK8s
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness


class TestCharm:
    @pytest.fixture(autouse=True)
    def setUp(self):
        self.harness = Harness(Route53LegoK8s)
        self.harness.begin()
        yield
        self.harness.cleanup()

    def create_and_grant_plugin_config_secret(self, content: dict[str, str]):
        id = self.harness.add_user_secret(content)
        self.harness.grant_secret(id, self.harness.charm.app.name)
        return id

    def test_given_email_is_valid_when_config_changed_then_status_is_active(self):
        self.harness.set_leader()
        id = self.create_and_grant_plugin_config_secret(
            {
                "aws-access-key-id": "dummy key",
                "aws-secret-access-key": "dummy access key",
                "aws-region": "dummy region",
                "aws-hosted-zone-id": "dummy zone id",
            }
        )
        self.harness.update_config({"email": "example@email.com", "route53-config-secret": id})
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus(
            "0/0 certificate requests are fulfilled"
        )

    def test_given_email_is_invalid_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader()
        id = self.create_and_grant_plugin_config_secret(
            {
                "aws-access-key-id": "dummy key",
                "aws-secret-access-key": "dummy access key",
                "aws-region": "dummy region",
                "aws-hosted-zone-id": "dummy zone id",
            }
        )
        self.harness.update_config({"email": "invalid-email", "route53-config-secret": id})
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("invalid email address")

    @pytest.mark.parametrize(
        "missing_option,secret_content",
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
        ],
    )
    def test_given_credentials_missing_when_config_changed_then_status_is_blocked(
        self, missing_option, secret_content
    ):
        self.harness.set_leader()
        id = self.create_and_grant_plugin_config_secret(secret_content)
        self.harness.update_config({"email": "example@email.com", "route53-config-secret": id})
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            f"the following config options must be set: {missing_option}"
        )
