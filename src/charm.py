#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Retrieves certificates from an ACME server using the aws route53 dns provider."""

import logging
from typing import Dict

from charms.acme_client_operator.v0.acme_client import AcmeClient  # type: ignore[import]
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class Route53AcmeOperatorCharm(AcmeClient):
    """Main class that is instantiated every time an event occurs."""

    def __init__(self, *args):
        """Uses the acme_client library to manage events."""
        super().__init__(*args, plugin="route53")
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    @property
    def _aws_access_key_id(self) -> str:
        """Returns aws access key from config."""
        return self.model.config.get("aws_access_key_id")

    @property
    def _aws_hosted_zone_id(self) -> str:
        """Returns aws hosted zone id from config."""
        return self.model.config.get("aws_hosted_zone_id")

    @property
    def _aws_secret_access_key(self) -> str:
        """Returns aws secret access key from config."""
        return self.model.config.get("aws_secret_access_key")

    @property
    def _aws_region(self):
        """Returns aws region from config."""
        return self.model.config.get("aws_region")

    @property
    def _aws_max_retries(self) -> str:
        """Returns aws max retries from config."""
        return self.model.config.get("aws_max_retries")

    @property
    def _aws_polling_interval(self) -> str:
        """Returns aws polling interval from config."""
        return self.model.config.get("aws_polling_interval")

    @property
    def _aws_propagation_timeout(self) -> str:
        """Returns aws propagation timeout from config."""
        return self.model.config.get("aws_propagation_timeout")

    @property
    def _aws_ttl(self) -> str:
        """Returns aws ttl from config."""
        return self.model.config.get("aws_ttl")

    @property
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command."""
        additional_config = {
            "AWS_REGION": self._aws_region,
            "AWS_HOSTED_ZONE_ID": self._aws_hosted_zone_id,
        }
        if self._aws_access_key_id:
            additional_config["AWS_ACCESS_KEY_ID"] = self._aws_access_key_id
        if self._aws_secret_access_key:
            additional_config["AWS_SECRET_ACCESS_KEY"] = self._aws_secret_access_key
        if self._aws_max_retries:
            additional_config["AWS_MAX_RETRIES"] = self._aws_max_retries
        if self._aws_polling_interval:
            additional_config["AWS_POLLING_INTERVAL"] = self._aws_polling_interval
        if self._aws_propagation_timeout:
            additional_config["AWS_PROPAGATION_TIMEOUT"] = self._aws_propagation_timeout
        if self._aws_ttl:
            additional_config["AWS_TTL"] = self._aws_ttl
        return additional_config

    def _on_config_changed(self, _):
        """Handles config-changed events."""
        if not self._aws_access_key_id or not self._aws_secret_access_key:
            self.unit.status = BlockedStatus(
                "aws-access-key-id, aws-secret-access-key must be set."
            )
            return
        if not self._aws_region:
            self.unit.status = BlockedStatus("aws-region must be set.")
            return
        if not self._aws_hosted_zone_id:
            self.unit.status = BlockedStatus("aws-hosted-zone-id must be set.")
            return
        try:
            self.validate_generic_acme_config()
        except ValueError as e:
            logger.error("Invalid config: %s", e)
            self.unit.status = BlockedStatus(str(e))
            return
        self.unit.status = ActiveStatus()


if __name__ == "__main__":  # pragma: nocover
    main(Route53AcmeOperatorCharm)
