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
- [Nix](https://determinate.systems/nix-installer/) with flakes enabled

## Install

```sh
nix profile install github:oknyshuk/fido-ssh-agent
systemctl --user mask gpg-agent-ssh.socket
systemctl --user enable --now \
  ~/.nix-profile/share/systemd/user/fido-ssh-agent.socket \
  ~/.nix-profile/share/systemd/user/fido-ssh-agent.service
```

Log out and back in for `SSH_AUTH_SOCK` to take effect. FIDO and regular SSH
keys then work transparently — the agent forwards non-FIDO requests to the
auto-discovered upstream agent (override with `FIDO_UPSTREAM_AUTH_SOCK`).

### On NixOS

The imperative `nix profile install` flow above also works on NixOS —
`systemctl --user enable /abs/path` is generic systemd behavior.

For a declarative install you need to wire systemd yourself, because NixOS's
user-systemd `UnitPath` searches `/etc/systemd/user` and `…/lib/systemd/user`
but not the `share/systemd/user/` we ship. The minimum is:

```nix
{ pkgs, ... }: {
  environment.systemPackages = [ pkgs.fido-ssh-agent ];
  systemd.packages = [ pkgs.fido-ssh-agent ];
  # systemd.packages registers the units; you still need to ask for them:
  systemd.user.sockets.fido-ssh-agent.wantedBy = [ "sockets.target" ];
  systemd.user.services.fido-ssh-agent.wantedBy = [ "default.target" ];
}
```

## Upgrade / uninstall

```sh
nix profile upgrade fido-ssh-agent
systemctl --user daemon-reload
systemctl --user restart fido-ssh-agent.service
# or:
systemctl --user disable --now fido-ssh-agent.socket fido-ssh-agent.service
systemctl --user unmask gpg-agent-ssh.socket
nix profile remove fido-ssh-agent
```

## Development

```sh
nix develop                             # devShell with rust toolchain
cargo run -- --socket /tmp/test.sock    # run against an ad-hoc socket
nix flake check                         # clippy + rustfmt + build
```
