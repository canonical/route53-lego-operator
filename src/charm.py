#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Retrieves certificates from an ACME server using the aws route53 dns provider."""

import logging
from typing import Optional, Dict

from ops.main import main
from charms.acme_client_operator.v0.acme_client import AcmeClient  # type: ignore[import]

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


class Route53LegoOperatorCharm(AcmeClient):
    """Main class that is instantiated every time an event occurs."""

    def __init__(self, *args):
        """Uses the acme_client library to manage events."""
        super().__init__(*args)

    @property
    def _aws_access_key_id(self):
        """Returns aws access key from config."""
        return self.model.config.get("aws_access_key_id")

    # Add properties for all config options from config.yaml
    # property for aws assume role arn
    @property
    def _aws_assume_role_arn(self):
        """Returns aws assume role arn from config."""
        return self.model.config.get("aws_assume_role_arn")

    @property
    def _aws_secret_access_key(self):
        """Returns aws secret access key from config."""
        return self.model.config.get("aws_secret_access_key")

    @property
    def _aws_region(self):
        """Returns aws region from config."""
        return self.model.config.get("aws_region")

    @property
    def _aws_hosted_zone_id(self):
        """Returns aws hosted zone id from config."""
        return self.model.config.get("aws_hosted_zone_id")

    @property
    def _aws_profile(self):
        """Returns aws profile from config."""
        return self.model.config.get("aws_profile")

    @property
    def _sdk_load_config(self):
        """Returns aws sdk load config from config."""
        return self.model.config.get("sdk_load_config")

    @property
    def _aws_max_retries(self):
        """Returns aws max retries from config."""
        return self.model.config.get("aws_max_retries")

    @property
    def _aws_polling_interval(self):
        """Returns aws polling interval from config."""
        return self.model.config.get("aws_polling_interval")

    @property
    def _aws_propagation_timeout(self):
        """Returns aws propagation timeout from config."""
        return self.model.config.get("aws_propagation_timeout")

    @property
    def _aws_ttl(self):
        """Returns aws ttl from config."""
        return self.model.config.get("aws_ttl")

    @property
    def _email(self) -> Optional[str]:
        """Returns email from config."""
        return self.model.config.get("email")

    @property
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command."""
        additional_config = {}
        if self._aws_access_key_id:
            additional_config["AWS_ACCESS_KEY_ID"] = self._aws_access_key_id
        if self._aws_assume_role_arn:
            additional_config["AWS_ASSUME_ROLE_ARN"] = self._aws_assume_role_arn
        if self._aws_secret_access_key:
            additional_config["AWS_SECRET_ACCESS_KEY"] = self._aws_secret_access_key
        if self._aws_region:
            additional_config["AWS_REGION"] = self._aws_region
        if self._aws_hosted_zone_id:
            additional_config["AWS_HOSTED_ZONE_ID"] = self._aws_hosted_zone_id
        if self._aws_profile:
            additional_config["AWS_PROFILE"] = self._aws_profile
        if self._sdk_load_config:
            additional_config["SDK_LOAD_CONFIG"] = self._sdk_load_config
        if self._aws_max_retries:
            additional_config["AWS_MAX_RETRIES"] = self._aws_max_retries
        if self._aws_polling_interval:
            additional_config["AWS_POLLING_INTERVAL"] = self._aws_polling_interval
        if self._aws_propagation_timeout:
            additional_config["AWS_PROPAGATION_TIMEOUT"] = self._aws_propagation_timeout
        if self._aws_ttl:
            additional_config["AWS_TTL"] = self._aws_ttl
        return additional_config

    @property
    def _plugin(self) -> str:
        """Returns plugin."""
        return "route53"


if __name__ == "__main__":  # pragma: nocover
    main(Route53LegoOperatorCharm)
