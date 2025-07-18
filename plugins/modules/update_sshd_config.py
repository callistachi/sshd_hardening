#!/usr/bin/python

# Copyright: (c) 2025, Callista Chi <hello@callistachi.com>
# Licensed under the MIT License
# See LICENSE file in the project root for full license details.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: update_sshd_config

short_description: An Ansible module for idempotently managing sshd_config settings. Useful for simplifying SSH daemon configuration updates.

version_added: "1.0.0"

description: 
  - This module allows you to easily configure SSH daemon settings
  - It supports most common SSH configuration options with proper validation
  - Automatically creates backups before making changes
  - Validates SSH configuration after changes

options:
  max_auth_tries:
    description: Maximum number of authentication attempts permitted per connection
    required: false
    type: int
      
  permit_root_login:
    description: Whether root can log in using ssh
    required: false
    type: str
    choices: ['yes', 'no', 'without-password', 'prohibit-password', 'forced-commands-only']

  password_authentication:
    description: Whether password authentication is allowed
    required: false
    type: bool
    choices: [true, false]

  pubkey_authentication:
    description: Whether public key authentication is allowed
    required: false
    type: bool
    choices: [true, false]

  challenge_response_authentication:
    description: Whether challenge-response authentication is allowed
    required: false
    type: bool
    choices: [true, false]

  protocol:
    description: SSH protocol version
    required: false
    type: int
    choices: [2]

  port:
    description: SSH port number
    required: false
    type: int

  x11_forwarding:
    description: Whether X11 forwarding is permitted
    required: false
    type: bool
    choices: [true, false]

  allow_tcp_forwarding:
    description: Whether TCP forwarding is permitted
    required: false
    type: bool
    choices: [true, false]

  allow_agent_forwarding:
    description: Whether ssh-agent forwarding is permitted
    required: false
    type: bool
    choices: [true, false]

  gateway_ports:
    description: Whether remote hosts are allowed to connect to local forwarded ports
    required: false
    type: bool
    choices: [true, false]

  permit_tunnel:
    description: Whether tun device forwarding is allowed
    required: false
    type: bool
    choices: [true, false]

  client_alive_interval:
    description: 
      - Timeout interval in seconds after which server will send a message to client
      - Set to 0 to disable.
    required: false
    type: int

  client_alive_count_max:
    description: Number of client alive messages sent without response before disconnection
    required: false
    type: int

  max_sessions:
    description: Maximum number of open sessions permitted per network connection
    required: false
    type: int

  max_startups:
    description: Maximum number of concurrent unauthenticated connections to SSH daemon
    required: false
    type: str

  allow_users:
    description: 
      - Space-separated list of user names allowed to log in
      - E.g. "user server workstation"
    required: false
    type: str

  deny_users:
    description: Space-separated list of user names not allowed to log in
    required: false
    type: str

  allow_groups:
    description: Space-separated list of group names allowed to log in
    required: false
    type: str

  deny_groups:
    description: Space-separated list of group names not allowed to log in
    required: false
    type: str

  log_level:
    description: SSH daemon log level
    required: false
    type: str
    choices: ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3']

  syslog_facility:
    description: Syslog facility code for SSH daemon
    required: false
    type: str
    choices: ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7']

  use_pam:
    description: Whether to use PAM for authentication
    required: false
    type: bool
    choices: [true, false]

  print_last_log:
    description: Whether to print the date and time of the last user login
    required: false
    type: bool
    choices: [true, false]

  tcp_keep_alive:
    description: Whether to send TCP keepalive messages
    required: false
    type: bool
    choices: [true, false]

  compression:
    description: Whether compression is allowed
    required: false
    type: bool
    choices: [true, false]

  permit_empty_passwords:
    description: Whether to allow empty passwords for SSH login
    required: false
    type: bool
    choices: [true, false]

  login_grace_time:
    description:
      - Time allowed for successful login before disconnecting
      - Can be specified as a number of seconds or time units like '30s', '2m'.
    required: false
    type: str

  ignore_rhosts:
    description: Whether to ignore .rhosts and .shosts files for authentication
    required: false
    type: bool
    choices: [true, false]

  banner:
    description: Path to the file containing the SSH login banner message
    required: false
    type: str

  hostbased_authentication:
    description: Whether to allow authentication using host-based authentication
    required: false
    type: bool
    choices: [true, false]

  rhosts_rsa_authentication:
    description: Whether to allow authentication using Rhosts RSA authentication
    required: false
    type: bool
    choices: [true, false]

  permit_user_environment:
    description: Whether to allow users to set environment variables.
    required: false
    type: bool

  config_file:
    description: Path to SSH daemon configuration file
    required: false
    type: path

  backup:
    description: Whether to create a backup of the configuration file
    required: false
    type: bool
    default: true
    choices: [true, false]

  backup_dir:
    description: Directory to store backup files
    required: false
    type: path
    default: /etc/ssh

  validate:
    description: Whether to validate SSH configuration after changes
    required: false
    type: bool
    default: true
    choices: [true, false]

  restart_service:
    description: Whether to restart SSH service after successful changes
    required: false
    type: bool
    default: false
    choices: [true, false]

  service_name:
    description: Name of the SSH service to restart
    required: false
    type: str
    default: ssh

author:
  - Callista Chi (@callistachi)
'''

EXAMPLES = r'''
- name: Basic SSH hardening
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    pubkey_authentication: true

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

- name: Check what changes would be made
  callistachi.sshd_config_manager.update_ssh_config:
    max_auth_tries: 3
    permit_root_login: "no"
    password_authentication: false
    check_mode: true
'''

RETURN = r'''
changed:
  description: Whether the SSH configuration was changed
  type: bool
  returned: always
  sample: true
    
msg:
  description: Description of changes made or current state
  type: str
  returned: always
  sample: "MaxAuthTries updated from 6 to 3; PermitRootLogin updated from yes to no"
  
changes:
  description: List of all changes made
  type: list
  returned: when changes are made
  sample: ["MaxAuthTries updated from 6 to 3", "PermitRootLogin updated from yes to no"]
    
backup_file:
  description: Path to the backup file created
  type: str
  returned: when backup is enabled
  sample: "/etc/ssh/sshd_config.backup.20250711-143022"
    
config_valid:
  description: Whether the SSH configuration is valid
  type: bool
  returned: when validate is true
  sample: true
    
service_restarted:
  description: Whether the SSH service was restarted
  type: bool
  returned: when restart_service is true and changes were made
  sample: true
'''


import os
import re
import shutil
import subprocess
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule


def get_current_ssh_setting(config_file, setting_name):
    """
    Get current value of setting from SSH config file

    Args:
        config_file: Path to SSH config file
        setting_name: SSH directive to look for

    Returns:
        tuple: (value, line_number, is_commented) or (None, None, None)

    Raises:
        IOError: If file cannot be read (permissions, encoding, etc.)
    """
    if not os.path.exists(config_file):
        return None, None, None

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except (IOError, UnicodeDecodeError) as e:
        raise IOError(f"Cannot read config file {config_file}: {str(e)}")

    for i, line in enumerate(lines):
        line = line.strip()

        if line.startswith('#'):
            match = re.search(
                rf'#\s*{re.escape(setting_name)}\s+(.+)', line, re.IGNORECASE)
            if match:
                return match.group(1).strip(), i, True

        elif re.match(rf'^{re.escape(setting_name)}\s+', line, re.IGNORECASE):
            match = re.search(
                rf'^{re.escape(setting_name)}\s+(.+)', line, re.IGNORECASE)
            if match:
                return match.group(1).strip(), i, False

    return None, None, None


def create_backup(config_file, backup_dir):
    """
    Create backup of SSH config with timestamp

    Args:
        config_file: Path to SSH config file to backup
        backup_dir: Directory to store backup in

    Returns:
        str: Path to created backup file
    """
    try:
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_name = f"{os.path.basename(config_file)}.backup.{timestamp}"
        backup_path = os.path.join(backup_dir, backup_name)

        shutil.copy2(config_file, backup_path)
        return backup_path
    except (OSError, IOError) as e:
        raise Exception(f"Failed to create backup: {str(e)}")


def validate_ssh_config(config_file):
    """
    Check if SSH config is valid using sshd -t

    Args:
        config_file: Path to SSH config file

    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        result = subprocess.run(
            ['sshd', '-t', '-f', config_file], capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stderr.strip()
    except FileNotFoundError:
        return False, "sshd command not found"
    except subprocess.TimeoutExpired:
        return False, "sshd validation timed out"
    except Exception as e:
        return False, f"Error running sshd validation: {str(e)}"


def update_ssh_setting(config_file, setting_name, new_value):
    """Update SSH setting in config file

    Args:
        config_file: Path to SSH config file
        setting_name: SSH directive to update
        new_value: New value for the setting

    Returns:
        tuple: (changed, old_value, new_value)
    """
    current_value, line_num, is_commented = get_current_ssh_setting(
        config_file, setting_name)

    if current_value == str(new_value) and not is_commented:
        return False, current_value, str(new_value)

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except (IOError, UnicodeDecodeError) as e:
        raise Exception(f"Cannot read config file: {str(e)}")

    new_line = f"{setting_name} {new_value}\n"

    if line_num is not None:
        lines[line_num] = new_line
    else:
        # Add new setting and try to group with similar auth settings
        insert_at = len(lines)
        auth_keywords = ['PasswordAuthentication',
                         'PubkeyAuthentication', 'PermitRootLogin']

        for i, line in enumerate(lines):
            if any(keyword in line for keyword in auth_keywords):
                insert_at = i + 1
                break

        lines.insert(insert_at, new_line)

    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except (IOError, UnicodeDecodeError) as e:
        raise Exception(f"Cannot write to config file: {str(e)}")

    return True, current_value, str(new_value)


def restart_ssh_service(module, service_name):
    """
    Restart SSH service using systemctl

    Args:
        module: AnsibleModule instance
        service_name: Name of the SSH service

    Returns:
        tuple: (success, error_message)
    """
    try:
        rc, stdout, stderr = module.run_command(['systemctl', 'restart', service_name])
        return rc == 0, stderr.strip()
    except Exception as e:
        return False, f"Error restarting service: {str(e)}"


def run_module():
    module_args = dict(
        # SSH Authentication Settings
        max_auth_tries=dict(
            type='int',
            required=False,
            default=None
        ),
        permit_root_login=dict(
            type='str',
            required=False,
            choices=['yes', 'no', 'without-password',
                     'prohibit-password', 'forced-commands-only'],
            default=None
        ),
        password_authentication=dict(
            type='bool',
            required=False,
            default=None
        ),
        pubkey_authentication=dict(
            type='bool',
            required=False,
            default=None
        ),
        challenge_response_authentication=dict(
            type='bool',
            required=False,
            default=None
        ),

        # SSH Protocol Settings
        protocol=dict(
            type='int',
            required=False,
            choices=[2],
            default=None
        ),
        port=dict(
            type='int',
            required=False,
            default=None
        ),

        # SSH Security Settings
        x11_forwarding=dict(
            type='bool',
            required=False,
            default=None
        ),
        allow_tcp_forwarding=dict(
            type='bool',
            required=False,
            default=None
        ),
        allow_agent_forwarding=dict(
            type='bool',
            required=False,
            default=None
        ),
        gateway_ports=dict(
            type='bool',
            required=False,
            default=None
        ),
        permit_tunnel=dict(
            type='bool',
            required=False,
            default=None
        ),

        # SSH Session Settings
        client_alive_interval=dict(
            type='int',
            required=False,
            default=None
        ),
        client_alive_count_max=dict(
            type='int',
            required=False,
            default=None
        ),
        max_sessions=dict(
            type='int',
            required=False,
            default=None
        ),
        max_startups=dict(
            type='str',
            required=False,
            default=None
        ),

        # SSH User Access Settings
        allow_users=dict(
            type='str',
            required=False,
            default=None
        ),
        deny_users=dict(
            type='str',
            required=False,
            default=None
        ),
        allow_groups=dict(
            type='str',
            required=False,
            default=None
        ),
        deny_groups=dict(
            type='str',
            required=False,
            default=None
        ),

        # SSH Logging Settings
        log_level=dict(
            type='str',
            required=False,
            choices=['QUIET', 'FATAL', 'ERROR', 'INFO',
                     'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'],
            default=None
        ),
        syslog_facility=dict(
            type='str',
            required=False,
            choices=['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1',
                     'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7'],
            default=None
        ),

        # SSH Misc Settings
        use_pam=dict(
            type='bool',
            required=False,
            default=None
        ),
        print_last_log=dict(
            type='bool',
            required=False,
            default=None
        ),
        tcp_keep_alive=dict(
            type='bool',
            required=False,
            default=None
        ),
        compression=dict(
            type='bool',
            required=False,
            default=None
        ),
        permit_empty_passwords=dict(
            type='bool',
            required=False,
            default=None
        ),
        login_grace_time=dict(
            type='int',
            required=False,
            default=None
        ),
        ignore_rhosts=dict(
            type='bool',
            required=False,
            default=None
        ),
        banner=dict(
            type='str',
            required=False,
            default=None
        ),
        hostbased_authentication=dict(
            type='bool',
            required=False,
            default=None
        ),
        rhosts_rsa_authentication=dict(
            type='bool',
            required=False,
            default=None
        ),
        permit_user_environment=dict(
            type='bool',
            required=False,
            default=None
        ),

        # Module Control Settings
        config_file=dict(
            type='path',
            default='/etc/ssh/sshd_config'
        ),
        backup=dict(
            type='bool',
            default=True
        ),
        backup_dir=dict(
            type='path',
            default='/etc/ssh'
        ),
        validate=dict(
            type='bool',
            default=True
        ),
        restart_service=dict(
            type='bool',
            default=False
        ),
        service_name=dict(
            type='str',
            default='ssh'
        )
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
        original_message='',
        message='',
        config_valid=True,
        changes=[]
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Extract parameters
    config_file = module.params['config_file']
    backup = module.params['backup']
    backup_dir = module.params['backup_dir']
    validate = module.params['validate']
    restart_service_flag = module.params['restart_service']
    service_name = module.params['service_name']

    # Build settings dictionary from non-None parameters
    settings_map = {
        'max_auth_tries': 'MaxAuthTries',
        'permit_root_login': 'PermitRootLogin',
        'password_authentication': 'PasswordAuthentication',
        'pubkey_authentication': 'PubkeyAuthentication',
        'challenge_response_authentication': 'ChallengeResponseAuthentication',
        'protocol': 'Protocol',
        'port': 'Port',
        'x11_forwarding': 'X11Forwarding',
        'allow_tcp_forwarding': 'AllowTcpForwarding',
        'allow_agent_forwarding': 'AllowAgentForwarding',
        'gateway_ports': 'GatewayPorts',
        'permit_tunnel': 'PermitTunnel',
        'client_alive_interval': 'ClientAliveInterval',
        'client_alive_count_max': 'ClientAliveCountMax',
        'max_sessions': 'MaxSessions',
        'max_startups': 'MaxStartups',
        'allow_users': 'AllowUsers',
        'deny_users': 'DenyUsers',
        'allow_groups': 'AllowGroups',
        'deny_groups': 'DenyGroups',
        'log_level': 'LogLevel',
        'syslog_facility': 'SyslogFacility',
        'use_pam': 'UsePAM',
        'print_last_log': 'PrintLastLog',
        'tcp_keep_alive': 'TCPKeepAlive',
        'compression': 'Compression',
        'permit_empty_passwords': 'PermitEmptyPasswords',
        'login_grace_time': 'LoginGraceTime',
        'ignore_rhosts': 'IgnoreRhosts',
        'banner': 'Banner',
        'hostbased_authentication': 'HostbasedAuthentication',
        'rhosts_rsa_authentication': 'RhostsRSAAuthentication',
        'permit_user_environment': 'PermitUserEnvironment'
    }

    # Convert boolean values to yes/no for SSH config
    def convert_bool_to_ssh(value):
        if isinstance(value, bool):
            return 'yes' if value else 'no'
        return value

    # Build settings to update
    settings_to_update = {}
    for param_name, ssh_name in settings_map.items():
        value = module.params.get(param_name)
        if value is not None:
            settings_to_update[ssh_name] = convert_bool_to_ssh(value)

    # Validate input
    max_auth_tries = module.params.get('max_auth_tries')
    if max_auth_tries is not None and (max_auth_tries < 1 or max_auth_tries > 100):
        module.fail_json(msg="max_auth_tries must be between 1 and 100")

    port = module.params.get('port')
    if port is not None and (port < 1 or port > 65535):
        module.fail_json(msg="port must be between 1 and 65535")

    client_alive_interval = module.params.get('client_alive_interval')
    if client_alive_interval is not None and client_alive_interval < 0:
        module.fail_json(msg="client_alive_interval must be 0 or greater")

    client_alive_count_max = module.params.get('client_alive_count_max')
    if client_alive_count_max is not None and client_alive_count_max < 0:
        module.fail_json(msg="client_alive_count_max must be 0 or greater")

    max_sessions = module.params.get('max_sessions')
    if max_sessions is not None and max_sessions < 1:
        module.fail_json(msg="max_sessions must be 1 or greater")

    # Check if no settings were provided
    if not settings_to_update:
        result['msg'] = "No SSH settings provided to update"
        module.exit_json(**result)

    # Check if config file exists
    if not os.path.exists(config_file):
        module.fail_json(msg=f"SSH config file not found: {config_file}")

    # Check if we have write permissions
    if not os.access(config_file, os.W_OK):
        module.fail_json(
            msg=f"No write permission for config file: {config_file}")

    # Return current state with no modifications if module run in check mode
    if module.check_mode:
        # In check mode report what would change
        changes_needed = []

        try:
            for ssh_name, new_value in settings_to_update.items():
                current_value, _, is_commented = get_current_ssh_setting(
                    config_file, ssh_name)
                if current_value != str(new_value) or is_commented:
                    changes_needed.append(
                        f"{ssh_name} would change from {current_value} to {new_value}")
        except Exception as e:
            module.fail_json(msg=f"Error checking current settings: {str(e)}")

        if changes_needed:
            result['changed'] = True
            result['msg'] = "Would make changes: " + "; ".join(changes_needed)
        else:
            result['msg'] = "No changes needed"

        module.exit_json(**result)

    # Create backup if requested
    backup_file = None
    if backup:
        try:
            backup_file = create_backup(config_file, backup_dir)
            result['backup_file'] = backup_file
        except Exception as e:
            module.fail_json(msg=f"Backup failed: {str(e)}")

    # Track all changes
    all_changes = []

    # Update each setting
    for setting_name, setting_value in settings_to_update.items():
        try:
            changed, old_value, new_value = update_ssh_setting(
                config_file, setting_name, setting_value)

            if changed:
                result['changed'] = True
                change_msg = f"{setting_name} updated from {old_value} to {new_value}"
                all_changes.append(change_msg)
            else:
                all_changes.append(
                    f"{setting_name} already set to {setting_value}")

        except Exception as e:
            # Restore backup if something went wrong
            if backup_file and os.path.exists(backup_file):
                try:
                    shutil.copy2(backup_file, config_file)
                    result['msg'] = f"Error updating {setting_name}: {str(e)}. Restored from backup."
                except Exception as restore_error:
                    result['msg'] = f"Error updating {setting_name}: {str(e)}. Failed to restore backup: {str(restore_error)}"
            else:
                result['msg'] = f"Error updating {setting_name}: {str(e)}"

            module.fail_json(**result)

    # Validate configuration if requested
    if validate:
        is_valid, error_msg = validate_ssh_config(config_file)
        result['config_valid'] = is_valid

        if not is_valid:
            # Restore backup if validation fails
            if backup_file and os.path.exists(backup_file):
                try:
                    shutil.copy2(backup_file, config_file)
                    result['msg'] = f"Configuration invalid, restored from backup: {error_msg}"
                    result['changed'] = False
                except Exception as restore_error:
                    result[
                        'msg'] = f"Configuration invalid: {error_msg}. Failed to restore backup: {str(restore_error)}"
            else:
                result['msg'] = f"Configuration invalid: {error_msg}"

            module.fail_json(**result)

    # Restart SSH service if requested and changes were made
    if restart_service_flag and result['changed']:
        success, error_msg = restart_ssh_service(module, service_name)
        if not success:
            result['msg'] = f"Settings updated but failed to restart service: {error_msg}"
            module.fail_json(**result)
        else:
            result['service_restarted'] = True

    # Set final message
    if all_changes:
        result['msg'] = "; ".join(all_changes)
        result['changes'] = all_changes
    else:
        result['msg'] = "No changes made"

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
