#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Retrieves certificates from an ACME server using the AWS Route53 dns provider."""

import logging
from typing import Dict

from charms.lego_base_k8s.v1.lego_client import AcmeClient
from ops.main import main

logger = logging.getLogger(__name__)


class Route53LegoK8s(AcmeClient):
    """Main class that is instantiated every time an event occurs."""

    REQUIRED_CONFIG = [
        "AWS_REGION",
        "AWS_HOSTED_ZONE_ID",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ]

    def __init__(self, *args):
        """Use the lego_client library to manage events."""
        super().__init__(*args, plugin="route53")

    def _validate_plugin_config(self, plugin_config: Dict[str, str]) -> str | None:
        """Check whether required config options are set.

        Returns:
            str: Error message if any required config options are missing.
        """
        required_fields = {
            "AWS_REGION",
            "AWS_HOSTED_ZONE_ID",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        }
        required_fields = plugin_config.keys()
        if missing_config := [
            option for option in required_fields if option not in required_fields
        ]:
            return f"The following config options must be set: {', '.join(missing_config)}"
        return None


if __name__ == "__main__":  # pragma: nocover
    main(Route53LegoK8s)
