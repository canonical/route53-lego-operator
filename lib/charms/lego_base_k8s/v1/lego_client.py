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
charmcraft fetch-lib charms.tls_certificates_interface.v3.tls_certificates
charmcraft fetch-lib charms.certificate_transfer_interface.v1.certificate_transfer
charmcraft fetch-lib charms.loki_k8s.v1.loki_push_api
```

You will also need to add the following library to the charm's `requirements.txt` file:
- pylego
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

    def _validate_plugin_config(self) -> str:
        if not self._api_key:
            return "API key was not provided"
        return ""

    @property
    def _plugin_config(self):
        return {}
```

Charms using this library are expected to:
- Inherit from AcmeClient
- Call `super().__init__(*args, plugin="")` with the lego plugin name
- Implement the `_validate_plugin_config` method,
  it should validate the plugin specific configuration,
  returning a string with an error message if the
  plugin specific configuration is invalid, otherwise an empty string.
- Specify a `{plugin-name}-config-secret` option in their `metadata.yaml` file:
```yaml
config:
  options:
    route53-config-secret:
      type: string
      description: The secret ID that contains the options for the plugin.
- Grant a secret to the charm that has the plugin speecific configuration options
  as a Dict[str,str]
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
from typing import Dict, Optional, Set
from urllib.parse import urlparse

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.tls_certificates_interface.v3.tls_certificates import (
    TLSCertificatesProvidesV3,
)
from cryptography import x509
from cryptography.x509.oid import NameOID
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
        self.tls_certificates = TLSCertificatesProvidesV3(self, CERTIFICATES_RELATION_NAME)
        self.cert_transfer = CertificateTransferProvides(self, CA_TRANSFER_RELATION_NAME)
        [
            self.framework.observe(event, self._configure)
            for event in [
                self.tls_certificates.on.certificate_creation_request,
                self.on.send_ca_cert_relation_joined,
                self.on.config_changed,
                self.on.update_status,
            ]
        ]
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)

        self._plugin = plugin

    def _on_collect_status(self, event: CollectStatusEvent) -> None:
        """Handle the collect status event."""
        if not (plugin_config := self._get_plugin_config_from_secret()):
            event.add_status(BlockedStatus("please grant the plugin config secret to the charm"))
            return
        if err := self._validate_plugin_config(plugin_config):
            event.add_status(BlockedStatus(err))
            return
        if err := self._validate_generic_acme_config():
            event.add_status(BlockedStatus(err))
            return
        event.add_status(ActiveStatus(self._get_certificate_fulfillment_status()))

    def _configure(self, event: EventBase) -> None:
        """Configure the Lego provider.

        Validate configs.
        Go through all the certificates relations and handle outstanding requests.
        Go Through all certificate transfer relations and share the CA certificates.
        """
        if not (plugin_config := self._get_plugin_config_from_secret()):
            logger.error("couldn't access the user secret with the plugin details.")
            return
        if err := self._validate_plugin_config(plugin_config):
            logger.error(err)
            return
        if err := self._validate_generic_acme_config():
            logger.error(err)
            return
        outstanding_requests = self.tls_certificates.get_outstanding_certificate_requests()
        for request in outstanding_requests:
            self._generate_signed_certificate(
                csr=request.csr,
                plugin_config=plugin_config,
                relation_id=request.relation_id,
            )
        if self._is_relation_created(CA_TRANSFER_RELATION_NAME):
            self.cert_transfer.add_certificates(self._get_issuing_ca_certificates())

    def _validate_generic_acme_config(self) -> str:
        """Validate generic ACME config.

        Returns:
        str: Error message if invalid, otherwise an empty string.
        """
        if not self._email:
            return "Email address was not provided"
        if not self._server:
            return "ACME server was not provided"
        if not self._email_is_valid(self._email):
            return "Invalid email address"
        if not self._server_is_valid(self._server):
            return "Invalid ACME server"
        return ""

    def _generate_signed_certificate(
        self, csr: str, plugin_config: Dict[str, str], relation_id: int
    ):
        """Generate signed certificate from the ACME provider."""
        if not self.unit.is_leader():
            logger.debug("Only the leader can handle certificate requests")
            return
        csr_subject = _get_subject_from_csr(csr)
        logger.info("Received Certificate Creation Request for domain %s", csr_subject)
        try:
            output = run_lego_command(
                csr=csr.encode(),
                email=self._email,
                server=self._server,
                env=plugin_config | self._app_environment,
                plugin=self._plugin,
            )
        except LEGOError as e:
            logger.error(
                "Failed to execute lego command: %s \
                will try again in during the next update status event.",
                e,
            )
            return
        logger.info("Received certificate for domain: %s", output.metadata.domain)
        self.tls_certificates.set_relation_certificate(
            certificate=output.certificate,
            certificate_signing_request=output.csr,
            ca=output.issuer_certificate,
            chain=[output.issuer_certificate, output.certificate],
            relation_id=relation_id,
        )

    def _get_issuing_ca_certificates(self) -> Set[str]:
        """Get a list of the CA certificates that have been used with the issued certs."""
        return {
            provider_certificate.ca
            for provider_certificate in self.tls_certificates.get_provider_certificates()
        }

    def _get_certificate_fulfillment_status(self) -> str:
        """Return the status message reflecting how many certificate requests are still pending."""
        outstanding_requests_num = len(
            self.tls_certificates.get_outstanding_certificate_requests()
        )
        total_requests_num = len(self.tls_certificates.get_requirer_csrs())
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

    @abstractmethod
    def _validate_plugin_config(self, plugin_config: Dict[str, str]) -> str | None:
        """Plugin specific configuration options for the charm.

        Implement this method in your charm to validate that the dictionary returned
        from the given user secret is valid.

        Args:
            plugin_config: The dictionary that is located in the user secret that will need to
            be validated.

        Returns:
            str: an error if any, otherwise None.
        """

    @staticmethod
    def _email_is_valid(email: str) -> bool:
        """Validate the format of the email address."""
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False
        return True

    @staticmethod
    def _server_is_valid(server: str) -> bool:
        """Validate the format of the ACME server address."""
        urlparts = urlparse(server)
        if not all([urlparts.scheme, urlparts.netloc]):
            return False
        return True

    @property
    def _email(self) -> Optional[str]:
        """Email address to use for the ACME account."""
        email = self.model.config.get("email", None)
        if not isinstance(email, str):
            return None
        return email

    @property
    def _server(self) -> Optional[str]:
        """ACME server address."""
        server = self.model.config.get("server", None)
        if not isinstance(server, str):
            return None
        return server

    ## Helpers
    def _is_relation_created(self, relation_name: str) -> bool:
        return bool(self.model.get_relation(relation_name))

    def _get_plugin_config_from_secret(self) -> Dict[str, str] | None:
        try:
            plugin_config_secret_id = str(
                self.model.config.get(f"{self._plugin}-config-secret", "")
            )
            plugin_config_secret: Secret = self.model.get_secret(id=plugin_config_secret_id)
            plugin_config = plugin_config_secret.get_content(refresh=True)
        except (SecretNotFoundError, ModelError):
            return None
        return plugin_config


def get_env_var(env_var: str) -> Optional[str]:
    """Get the environment variable value.

    Looks for all upper-case and all low-case of the `env_var`.

    Args:
        env_var: Name of the environment variable.

    Returns:
        Value of the environment variable. None if not found.
    """
    return os.environ.get(env_var.upper(), os.environ.get(env_var.lower(), None))


def _get_subject_from_csr(certificate_signing_request: str) -> str:
    """Return subject from a provided CSR."""
    csr = x509.load_pem_x509_csr(certificate_signing_request.encode())
    subject_value = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if isinstance(subject_value, bytes):
        return subject_value.decode()
    else:
        return str(subject_value)
