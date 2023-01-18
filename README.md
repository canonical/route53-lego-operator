# route53-lego-operator

## Description

AWS Route53 LEGO operator implements the provider side of the `tls-certificates-interface`
to provide signed certificates from an ACME servers, using LEGO
(https://go-acme.github.io/lego).
It uses the  `acme_client` library to get the certificate from the ACME server.

## Usage

Deploy route53-lego-operator`:

If you wish to change the default configuration, create a YAML configuration file with fields you would like to change:


```yaml
route53-lego:
  email: <Account email address>
  aws_access_key_id: <AWS Access Key ID>
   aws_secret_access_key: <AWS Secret Access Key>
   aws_region: <AWS Region>
```
`juju deploy route53-lego-operator --config <yaml config file>`

Relate it to a `tls-certificates-requirer` charm:

`juju relate route53-lego-operator:certificates tls-certificates-requirer`

## Config

### Required configuration properties
```
email: <Account email address>
aws_access_key_id: <AWS Access Key ID>
aws_secret_access_key: <AWS Secret Access Key>
aws_region: <AWS Region>
```

### Optional configuration properties
```
aws_max_retries: <The number of maximum returns the service will use to make an individual API request>
aws_polling_interval: <Time between DNS propagation checks in seconds>
aws_propagation_timeout: <Maximum waiting time for DNS propagation in seconds>
aws_ttl: <The TTL of the TXT record used for the DNS challenge>
```

## Relations

`certificates`: `tls-certificates-interface` provider

## OCI Images

This charm uses a [Lego](https://github.com/canonical/lego-rock) image that is built using Rockcraft.
`ghcr.io/canonical/lego:4.9.1`

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this
charm following best practice guidelines, and
[CONTRIBUTING.md](https://github.com/canonical/route53-lego-operator/blob/main/CONTRIBUTING.md) for developer
guidance.
