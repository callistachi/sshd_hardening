# callistachi.sshd_config_manager - SSHD Configuration Ansible Collection
[![Galaxy](https://img.shields.io/badge/Galaxy-callistachi.sshd__config__manager-blue?logo=ansible)](https://galaxy.ansible.com/ui/repo/published/callistachi/sshd_config_manager/)


## Table of Contents

- [Overview](#overview)
- [Module Included](#module-included)
- [Features](#features)
- [Requirements](#requirements)
- [Compatibility](#compatibility)
- [Installation](#installation)
- [Usage Example](#usage-example)
- [Why Use This Module Instead of `lineinfile` or Manual Playbooks?](#why-use-this-module-instead-of-lineinfile-or-manual-playbooks)
- [Module Documentation](#module-documentation)
- [License Information](#license-information)

## Overview
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
### Using Ansible Galaxy (recommended)

You can install the collection directly from Ansible Galaxy:

```bash
ansible-galaxy collection install callistachi.sshd_config_manager
```

[View on Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/callistachi/sshd_config_manager/)

Or add it to your `requirements.yml`:

```yaml
collections:
  - name: callistachi.sshd_config_manager
```

Then install with:

```bash
ansible-galaxy install -r requirements.yml
```

### Manual Installation
If you've downloaded the .tar.gz file directly from the [Github Releases](https://github.com/callistachi/sshd_config_manager/releases) page:

```bash
ansible-galaxy collection install /path/to/callistachi.sshd_config_manager.tar.gz
```

## Usage Example
**Basic SSH hardening**
```yaml
- name: Basic SSH hardening
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    pubkey_authentication: true
```
**More comprehensive SSH hardening**
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
**Check what changes would be made**
```yaml
- name: Check what changes would be made
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    check_mode: true
```

## Why Use This Module Instead of `lineinfile` or Manual Playbooks?

When managing `sshd_config`, many users rely on `lineinfile` or similar Ansible modules. While these work for simple changes, this module offers significant advantages:

| Feature                | Using `lineinfile` / Manual Playbook                 | Using `update_sshd_config` Module               |
|------------------------|-----------------------------------------------------|------------------------------------------------|
| **Idempotency**        | Requires careful regex; risk of duplicates or misses| Parses config intelligently; updates cleanly    |
| **Readability**        | Multiple tasks per setting, verbose and repetitive  | Single task with clear settings dictionary      |
| **Error Handling**     | Prone to malformed configs, broken syntax            | Safer edits preserving comments and formatting |
| **Maintainability**    | Harder to maintain as complexity grows               | Easier to maintain and reuse across projects    |
| **Usability**          | Requires deeper Ansible and regex knowledge          | Simple YAML dictionary for settings             |

### Example

**Using `lineinfile`:**

```yaml
- name: Disable root login
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^PermitRootLogin'
    line: 'PermitRootLogin no'
    create: yes

- name: Disable password authentication
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^PasswordAuthentication'
    line: 'PasswordAuthentication no'
    create: yes
```

**Using `update_sshd_config` module:**
```yaml
- name: Harden SSH configuration
  callistachi.sshd_config_manager.update_sshd_config:
    permit_root_login: no
    password_authentication: no
    restart_service: yes
```

## Module Documentation

For full details on all available parameters, see the [update_sshd_config module README](./plugins/modules/update_sshd_config.md).


## License Information
This collection is licensed under the [MIT License](README.md).
