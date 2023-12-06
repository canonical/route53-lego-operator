# Route53 LEGO Operator (K8s)
[![CharmHub Badge](https://charmhub.io/route53-lego-k8s/badge.svg)](https://charmhub.io/route53-lego-k8s)

Let's Encrypt certificates in the Juju ecosystem for AWS route53 users.

# Pre-requisites

This charm is a provider of the [`tls-certificates-interface`](https://github.com/canonical/tls-certificates-interface), 
charms that require Let's Encrypt certificates need to implement the requirer side.

## Usage

Create a YAML configuration file with the following fields:

```yaml
route53-lego-k8s:
  email: <Account email address>
  aws_access_key_id: <AWS Access Key ID>
  aws_secret_access_key: <AWS Secret Access Key>
  aws_region: <AWS Region>
  aws_hosted_zone_id: <AWS Hosted Zone ID>
```

Deploy `route53-lego-k8s`:

```bash
juju deploy route53-lego-k8s --config <yaml config file>
```

Relate it to a `tls-certificates-requirer` charm:

```bash
juju relate route53-lego-k8s:certificates <tls-certificates-requirer>
````

## Config

### Required configuration properties

- email: Let's Encrypt email address
- aws_access_key_id: AWS Access Key ID
- aws_secret_access_key: AWS Secret Access Key
- aws_region: AWS Region
- aws_hosted_zone_id: AWS Hosted Zone ID

### Optional configuration properties

- server: Let's Encrypt server to use (default: `https://acme-v02.api.letsencrypt.org/directory`)
- aws_max_retries: The number of maximum returns the service will use to make an individual API request (default: `5`)
- aws_polling_interval: Time (in seconds) between DNS propagation checks in seconds (default: `15`)
- aws_propagation_timeout: Maximum waiting time (in seconds) for DNS propagation in seconds (default: `3600`)
- aws_ttl: The TTL of the TXT record used for the DNS challenge (default: `120`)

## Relations

- `certificates`: `tls-certificates-interface` provider

## OCI Images

-  [Lego Rock Image](https://github.com/canonical/lego-rock)
