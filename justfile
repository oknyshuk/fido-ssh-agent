unit_dir := env("HOME") / ".config/systemd/user"
autostart_dir := env("HOME") / ".config/autostart"

build:
    nix build

check:
    cargo clippy

install: build
    nix profile install . 2>/dev/null || nix profile upgrade '.*fido-ssh-agent.*'
    mkdir -p {{ unit_dir }} {{ autostart_dir }}
    cp systemd/fido-ssh-agent.socket {{ unit_dir }}/
    cp systemd/fido-ssh-agent.service {{ unit_dir }}/
    cp /etc/xdg/autostart/gnome-keyring-ssh.desktop {{ autostart_dir }}/
    echo "Hidden=true" >> {{ autostart_dir }}/gnome-keyring-ssh.desktop
    systemctl --user mask gpg-agent-ssh.socket
    systemctl --user daemon-reload
    systemctl --user enable --now fido-ssh-agent.socket fido-ssh-agent.service

uninstall:
    -systemctl --user disable --now fido-ssh-agent.socket fido-ssh-agent.service
    -rm -f {{ unit_dir }}/fido-ssh-agent.socket
    -rm -f {{ unit_dir }}/fido-ssh-agent.service
    -rm -f {{ autostart_dir }}/gnome-keyring-ssh.desktop
    -systemctl --user unmask gpg-agent-ssh.socket
    -systemctl --user daemon-reload
    -nix profile remove '.*fido-ssh-agent.*'

dev socket="/tmp/fido-test.sock":
    cargo run -- --socket {{ socket }}
