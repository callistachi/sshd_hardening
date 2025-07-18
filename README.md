# sshd_config_manager

This Ansible collection provides a simple, idempotent way to manage `sshd_config` files on remote systems.  
It is designed to make maintaining SSH server configuration easier and safer in automated environments.

## Module Included

- `update_sshd_config`: A custom Ansible module to programmatically manage OpenSSH server configuration options.

## Features

- Supports over 30 common SSHD settings
- Backs up the original configuration before making changes
- Validates the new config using `sshd -t`
- Supports check mode (`--check`)
- Optionally restarts the SSH service after applying changes
- Detects and updates commented-out values
- Ensures idempotency

## Requirements

- Python 3.x
- Ansible 2.10+
- Target host must have:
  - `sshd`
  - `systemctl` (for service restarts)
  - Write permissions to `/etc/ssh/sshd_config` (or custom config path)

## Compatibility

This module has been tested on:

- RHEL/CentOS 7+
- Fedora
- Debian 10+
- Ubuntu 18.04+

It should work on any Linux distribution where:

- The SSH daemon is OpenSSH-based
- The config is located at `/etc/ssh/sshd_config` (or specified via `config_file`)
- The system uses `systemctl` or `service` to manage SSH

If your distribution uses a different init system or service name, set the `service_name` manually and ensure Ansible has the correct privileges to restart it.


## Installation

If not using Galaxy, you can include it manually:

```bash
ansible-galaxy collection install callistachi.sshd_config_manager
```

## Usage Example
### Basic SSH hardening
```yaml
- name: Basic SSH hardening
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    pubkey_authentication: true
```
### More comprehensive SSH hardening
```yaml
- name: Comprehensive SSH hardening
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    pubkey_authentication: true
    protocol: 2
    port: 2222
    x11_forwarding: false
    allow_tcp_forwarding: false
    allow_agent_forwarding: false
    client_alive_interval: 300
    client_alive_count_max: 2
    max_sessions: 2
    allow_users: "admin deploy"
    restart_service: true
```
### Check what changes would be made
```yaml
- name: Check what changes would be made
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    check_mode: true
```

## License Information
This collection is licensed under the [MIT License](README.md).
