# fido-ssh-agent

Linux SSH agent for FIDO2 security keys. Plug in your key, enter PIN once, then touch to sign.

- Auto-detects FIDO2 keys via udev hotplug
- Enumerates resident `ssh:` credentials over CTAP2
- Caches PIN per device - prompts once on plug-in, reuses for all signs
- Proxies non-FIDO keys to upstream agent (gnome-keyring, ssh-agent, gpg-agent)
- Systemd socket activation with readiness notification

## Requirements

- Linux with hidraw access (systemd v252+ or `libu2f-udev`)
- A FIDO2 key with resident SSH credentials (`ssh-keygen -t ed25519-sk -O resident`)
- Nix

## Install

```bash
curl -fsSL https://install.determinate.systems/nix | sh -s -- install
nix develop -c just install
```

Log out and back in for `SSH_AUTH_SOCK` to take effect.

Both FIDO and regular SSH keys work transparently - the agent auto-discovers
the upstream agent (gnome-keyring, ssh-agent, gpg-agent) and forwards
non-FIDO requests to it. Override with `FIDO_UPSTREAM_AUTH_SOCK` if needed.

## Development

```bash
nix develop                           # enter dev shell
just dev socket=/tmp/other.sock       # custom socket path
just check                            # cargo clippy
```
