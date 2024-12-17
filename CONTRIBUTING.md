# Contributing

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

This project uses `uv`. You can install it on Ubuntu with:

```shell
sudo snap install --classic astral-uv
```

You can create an environment for development with `uv`:

```shell
uv sync
```

## Testing

This project uses `tox` for managing test environments. It can be installed
with:

```shell
uv tool install tox --with tox-uv
```

There are some pre-configured environments that can be used for linting
and formatting code when you're preparing contributions to the charm:

## Build
Building and publishing charms is done using charmcraft (official documentation
[here](https://juju.is/docs/sdk/publishing)). You can install charmcraft using `snap`:

```bash
sudo snap install charmcraft --channel=classic
```

Initialize LXD:

```bash
lxd init --auto
```

Go to the charm directory and run:

```bash
charmcraft pack
```
