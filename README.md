# route53-acme-operator

## Description

AWS Route53 ACME operator implements the provider side of the `tls-certificates-interface`
to provide signed certificates from an ACME servers, using LEGO
(https://go-acme.github.io/lego).

## Usage

`Deploy route53-acme-operator`:

Create a YAML configuration file with the following fields:


```yaml
route53-acme-operator:
  email: <Account email address>
  aws_access_key_id: <AWS Access Key ID>
  aws_secret_access_key: <AWS Secret Access Key>
  aws_region: <AWS Region>
```
`juju deploy route53-acme-operator --config <yaml config file>`

Relate it to a `tls-certificates-requirer` charm:

`juju relate route53-acme-operator:certificates <tls-certificates-requirer>`

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

-  [Lego Rock Image](https://github.com/canonical/lego-rock)

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this
charm following best practice guidelines, and
[CONTRIBUTING.md](https://github.com/canonical/route53-acme-operator/blob/main/CONTRIBUTING.md) for developer
guidance.
