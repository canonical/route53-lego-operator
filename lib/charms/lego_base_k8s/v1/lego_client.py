# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""# lego_client Library.

This library is designed to enable developers to easily create new charms for the ACME protocol.
This library contains all the logic necessary to get certificates from an ACME server.

## Getting Started
To get started using the library, you need to fetch the library using `charmcraft`.
```shell
charmcraft fetch-lib charms.lego_client_operator.v1.lego_client
```

You will also need the following libraries:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v4.tls_certificates
charmcraft fetch-lib charms.certificate_transfer_interface.v1.certificate_transfer
charmcraft fetch-lib charms.loki_k8s.v1.loki_push_api
```

You will also need to add the following library to the charm's `requirements.txt` file:
- jsonschema
- cryptography
- cosl

Then, to use the library in an example charm, you can do the following:
```python
from charms.lego_client_operator.v1.lego_client import AcmeClient
from ops.main import main
class ExampleAcmeCharm(AcmeClient):
    def __init__(self, *args):
        super().__init__(*args, plugin="namecheap")
        self._server = "https://acme-staging-v02.api.letsencrypt.org/directory"
        self._email = "testingmctestface@test.com"

    def _validate_plugin_config(self, plugin_config: Dict[str, str]) -> str:
        if "NAMECHEAP_API_USER" not in plugin_config:
            return "API user was not"
        if "NAMECHEAP_API_KEY" not in plugin_config:
            return "API key was not provided"
        return ""
```

Charms using this library are expected to:
- Inherit from AcmeClient
- Call `super().__init__(*args, plugin="")` with the lego plugin name
- Implement the `_validate_plugin_config` method,
  it should validate the plugin specific configuration,
  returning a string with an error message if the
  plugin specific configuration is invalid, otherwise an empty string.
- Specify a config option in the metadata.yaml file:
``yaml
config:
  options:
    <plugin>-config-secret:
      type: string
      description: The secret ID that contains the options for the plugin.
- Create a secret that contains all of the required parameters for the plugin.
- Grant this secret to the charm and store the secret id in the previously defined config option.
- Specify a `certificates` integration in their
  `metadata.yaml` file:
```yaml
provides:
  certificates:
    interface: tls-certificates
  send-ca-cert:
    interface: certificate_transfer
```
- Specify a `logging` integration in their `metadata.yaml` file:
```yaml
requires:
  logging:
    interface: loki_push_api
```
"""

import abc
import logging
import os
import re
from abc import abstractmethod
from typing import Dict, Set
from urllib.parse import urlparse

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    TLSCertificatesProvidesV4,
)
from ops import ModelError, Secret, SecretNotFoundError
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import EventBase
from ops.model import ActiveStatus, BlockedStatus
from pylego.pylego import LEGOError, run_lego_command

# The unique Charmhub library identifier, never change it
LIBID = "d67f92a288e54ab68a6b6349e9b472c4"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0


logger = logging.getLogger(__name__)

CERTIFICATES_RELATION_NAME = "certificates"
CA_TRANSFER_RELATION_NAME = "send-ca-cert"


class AcmeClient(CharmBase):
    """Base charm for charms that use the ACME protocol to get certificates.

    This charm implements the tls_certificates interface as a provider.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, *args, plugin: str):
        super().__init__(*args)
        self._logging = LogForwarder(self, relation_name="logging")
        self.tls_certificates = TLSCertificatesProvidesV4(self, CERTIFICATES_RELATION_NAME)
        self.cert_transfer = CertificateTransferProvides(self, CA_TRANSFER_RELATION_NAME)

        [
            self.framework.observe(event, self._configure)
            for event in [
                self.on[CA_TRANSFER_RELATION_NAME].relation_joined,
                self.on[CERTIFICATES_RELATION_NAME].relation_changed,
                self.on.config_changed,
                self.on.update_status,
            ]
        ]
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)

        self._plugin = plugin

    def _on_collect_status(self, event: CollectStatusEvent) -> None:
        """Handle the collect status event."""
        if err := self.validate_generic_acme_config():
            event.add_status(BlockedStatus(err))
            return
        if not self._plugin_config:
            event.add_status(BlockedStatus("plugin config secret invalid or not found"))
            return
        if err := self._validate_plugin_config(self._plugin_config):
            event.add_status(BlockedStatus(err))
            return
        event.add_status(ActiveStatus(self._get_certificate_fulfillment_status()))

    def _configure(self, event: EventBase) -> None:
        """Configure the Lego provider.

        Validate configs.
        Go through all the certificates relations and handle outstanding requests.
        Go Through all certificate transfer relations and share the CA certificates.
        """
        if err := self.validate_generic_acme_config():
            logger.error(err)
            return
        if err := self._validate_plugin_config(self._plugin_config):
            logger.error(err)
            return
        outstanding_requests = self.tls_certificates.get_outstanding_certificate_requests()
        for request in outstanding_requests:
            self._generate_signed_certificate(
                csr=request.certificate_signing_request,
                relation_id=request.relation_id,
            )
        if len(self.model.relations.get(CA_TRANSFER_RELATION_NAME, [])) > 0:
            self.cert_transfer.add_certificates(self._get_issuing_ca_certificates())

    @abstractmethod
    def _validate_plugin_config(self, plugin_config: Dict[str, str]) -> str:
        """Validate plugin specific configuration.

        Implementations need to validate the plugin
        specific configuration that is received as the
        first argument of the function and return either
        an empty string if valid or the error message if invalid.

        Returns:
            str: Error message if invalid, otherwise an empty string.
        """
        pass

    def validate_generic_acme_config(self) -> str:
        """Validate generic ACME config.

        Returns:
        str: Error message if invalid, otherwise an empty string.
        """
        if not self._email:
            return "Email address was not provided"
        if not self._server:
            return "ACME server was not provided"
        if not _email_is_valid(self._email):
            return "Invalid email address"
        if not _server_is_valid(self._server):
            return "Invalid ACME server"
        return ""

    def _generate_signed_certificate(self, csr: CertificateSigningRequest, relation_id: int):
        """Generate signed certificate from the ACME provider."""
        if not self.unit.is_leader():
            logger.debug("Only the leader can handle certificate requests")
            return
        logger.info("Received Certificate Creation Request for domain %s", csr.common_name)
        try:
            response = run_lego_command(
                email=self._email,
                server=self._server,
                csr=csr.raw.encode(),
                env=self._plugin_config | self._app_environment,
                plugin=self._plugin,
            )
        except LEGOError as e:
            logger.error(
                "An error occured executing the lego command: %s \
                will try again in during the next update status event.",
                e,
            )
            return
        self.tls_certificates.set_relation_certificate(
            provider_certificate=ProviderCertificate(
                certificate=Certificate.from_string(response.certificate),
                certificate_signing_request=response.csr,
                ca=Certificate.from_string(response.issuer_certificate),
                chain=[
                    Certificate.from_string(cert)
                    for cert in [response.certificate, response.issuer_certificate]
                ],
                relation_id=relation_id,
            ),
        )

    def _get_issuing_ca_certificates(self) -> Set[str]:
        """Get a list of the CA certificates that have been used with the issued certs."""
        return {
            str(provider_certificate.ca)
            for provider_certificate in self.tls_certificates.get_provider_certificates()
        }

    def _get_certificate_fulfillment_status(self) -> str:
        """Return the status message reflecting how many certificate requests are still pending."""
        outstanding_requests_num = len(
            self.tls_certificates.get_outstanding_certificate_requests()
        )
        total_requests_num = len(self.tls_certificates.get_certificate_requests())
        fulfilled_certs = total_requests_num - outstanding_requests_num
        return f"{fulfilled_certs}/{total_requests_num} certificate requests are fulfilled"

    @property
    def _app_environment(self) -> Dict[str, str]:
        """Extract proxy model environment variables."""
        env = {}

        if http_proxy := get_env_var(env_var="JUJU_CHARM_HTTP_PROXY"):
            env["HTTP_PROXY"] = http_proxy
        if https_proxy := get_env_var(env_var="JUJU_CHARM_HTTPS_PROXY"):
            env["HTTPS_PROXY"] = https_proxy
        if no_proxy := get_env_var(env_var="JUJU_CHARM_NO_PROXY"):
            env["NO_PROXY"] = no_proxy
        return env

    @property
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command.

        Implement this method in your charm to return a dictionary with the plugin specific
        configuration.

        Returns:
            Dict[str,str]: Plugin specific configuration.
        """
        try:
            plugin_config_secret_id = str(
                self.model.config.get(f"{self._plugin}-config-secret", "")
            )
            plugin_config_secret: Secret = self.model.get_secret(id=plugin_config_secret_id)
            plugin_config = plugin_config_secret.get_content(refresh=True)
        except (SecretNotFoundError, ModelError):
            return {}
        return plugin_config

    @property
    def _email(self) -> str | None:
        """Email address to use for the ACME account."""
        email = self.model.config.get("email", None)
        if not isinstance(email, str):
            return None
        return email

    @property
    def _server(self) -> str | None:
        """ACME server address."""
        server = self.model.config.get("server", None)
        if not isinstance(server, str):
            return None
        return server


def get_env_var(env_var: str) -> str | None:
    """Get the environment variable value.

    Looks for all upper-case and all low-case of the `env_var`.

    Args:
        env_var: Name of the environment variable.

    Returns:
        Value of the environment variable. None if not found.
    """
    return os.environ.get(env_var.upper(), os.environ.get(env_var.lower(), None))


def _email_is_valid(email: str) -> bool:
    """Validate the format of the email address."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False
    return True


def _server_is_valid(server: str) -> bool:
    """Validate the format of the ACME server address."""
    urlparts = urlparse(server)
    if not all([urlparts.scheme, urlparts.netloc]):
        return False
    return True
