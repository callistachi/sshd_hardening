import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
import subprocess
import stat

# Get the absolute path to the collection root
collection_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..")
)
module_path = os.path.join(collection_root, "plugins", "modules")
sys.path.insert(0, module_path)

from update_sshd_config import (
    get_current_ssh_setting,
    create_backup,
    validate_ssh_config,
    update_ssh_setting,
    restart_ssh_service,
)


@pytest.fixture
def ssh_config_with_setting_active(tmp_path):
    """Creates a temporary SSH config file for testing getting the current value of an active setting"""
    content = "X11Forwarding yes"
    config_file = tmp_path / "sshd_config"
    config_file.write_text(content)
    return str(config_file)


@pytest.fixture
def ssh_config_with_setting_commented(tmp_path):
    """Creates a temporary SSH config file for testing getting the current value of a commented setting"""
    content = "#PasswordAuthentication no"
    config_file = tmp_path / "sshd_config"
    config_file.write_text(content)
    return str(config_file)


@pytest.fixture
def ssh_config_file(tmp_path):
    """Creates a temporary SSH config file for testing backups"""
    content = """
X11Forwarding yes
PasswordAuthentication no
Port 22
    """
    config_file = tmp_path / "sshd_config"
    config_file.write_text(content)
    return str(config_file)


@pytest.fixture
def backup_directory(tmp_path):
    """Creates a backup directory for testing backups"""
    backup_dir = tmp_path / "backups"
    return str(backup_dir)


@pytest.fixture
def existing_backup_directory(tmp_path):
    """Creates an existing backup directory for testing backups"""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    return str(backup_dir)


@pytest.fixture
def readonly_backup_directory(tmp_path):
    """Creates a read-only backup directory for testing permission permission errors"""
    backup_dir = tmp_path / "readonly_backups"
    backup_dir.mkdir()
    backup_dir.chmod(0o444)
    return str(backup_dir)


@pytest.fixture
def ssh_config_valid(tmp_path):
    """Creates a valid SSH config file for validation testing"""
    hostkey_file = tmp_path / "ssh_host_rsa_key"

    subprocess.run([
        'ssh-keygen', '-t', 'rsa', '-b', '2048', 
        '-f', str(hostkey_file), '-N', '', '-q'
    ], check=True)
    
    hostkey_file.chmod(0o600)
    
    content = f"""X11Forwarding yes
PasswordAuthentication no
Port 22
HostKey {hostkey_file}
"""
    config_file = tmp_path / "sshd_config"
    config_file.write_text(content)
    return str(config_file)


@pytest.fixture
def ssh_config_invalid(tmp_path):
    """Creates an invalid SSH config file for validation testing"""
    hostkey_file = tmp_path / "ssh_host_rsa_key"

    subprocess.run([
        'ssh-keygen', '-t', 'rsa', '-b', '2048', 
        '-f', str(hostkey_file), '-N', '', '-q'
    ], check=True)
    
    hostkey_file.chmod(0o600)
    content = """X12Forwarding yes
PwdAuthentication no
Port 222222
"""
    config_file = tmp_path / "sshd_config"
    config_file.write_text(content)
    return str(config_file)

@pytest.fixture
def ssh_config_with_auth_settings(tmp_path):
    """Creates a config with multiple auth-related settings for testing insertion logic"""
    content = f"""X11Forwarding yes
Port 22
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
X11Forwarding yes
"""
    config_file = tmp_path / "sshd_config"
    config_file.write_text(content)
    return str(config_file)


def test_get_current_ssh_setting_active(ssh_config_with_setting_active):
    """Tests the get_current_ssh_setting function with an active setting"""
    value, line_num, is_commented = get_current_ssh_setting(
        ssh_config_with_setting_active, "X11Forwarding"
    )

    assert value == "yes"
    assert line_num == 0
    assert is_commented is False


def test_get_current_ssh_setting_commented(ssh_config_with_setting_commented):
    """Tests the get_current_ssh_setting function with a commented setting"""
    value, line_num, is_commented = get_current_ssh_setting(
        ssh_config_with_setting_commented, "PasswordAuthentication"
    )

    assert value == "no"
    assert line_num == 0
    assert is_commented is True


def test_create_backup_with_mocked_time(ssh_config_file, backup_directory):
    """Test the create_backup function with a controlled timestamped backup directory"""
    fake_time = datetime(2025, 7, 16, 14, 42, 5)

    with patch("update_sshd_config.datetime") as mock_datetime:
        mock_datetime.now.return_value = fake_time

        backup_path = create_backup(ssh_config_file, backup_directory)

        expected_filename = "sshd_config.backup.20250716-144205"
        expected_path = os.path.join(backup_directory, expected_filename)

        assert backup_path == expected_path
        assert os.path.exists(backup_path)


def test_validate_ssh_config_valid(ssh_config_valid):
    """Tests the test_validate_ssh_config function with a valid ssh config"""
    is_valid, error_msg = validate_ssh_config(ssh_config_valid)
    print(f"Debug - is_valid: {is_valid}, error_msg: '{error_msg}'")
    assert is_valid is True
    assert error_msg == ""


def test_validate_ssh_config_invalid(ssh_config_invalid):
    """Tests the test_validate_ssh_config function with an invalid ssh config"""
    is_valid, error_msg = validate_ssh_config(ssh_config_invalid)
    assert is_valid is False
    assert error_msg


def test_validate_ssh_config_file_not_found():
    """Tests the test_validate_ssh_config function with an invalid path"""
    is_valid, error_msg = validate_ssh_config("/nonexistent/file")
    assert is_valid is False
    assert error_msg


def test_update_ssh_setting_modify_active_setting(ssh_config_with_setting_active):
    """Tests the update_ssh_setting with an active setting to a new value"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_setting_active, "X11Forwarding", "no"
    )

    assert changed is True
    assert old_value == "yes"
    assert new_value == "no"

    value, line_num, is_commented = get_current_ssh_setting(
        ssh_config_with_setting_active, "X11Forwarding"
    )
    assert value == "no"
    assert is_commented is False


def test_update_ssh_setting_no_change_needed_active(ssh_config_with_setting_active):
    """Tests the update_ssh_setting with a setting that is already desired"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_setting_active, "X11Forwarding", "yes"
    )

    assert changed is False
    assert old_value == "yes"
    assert new_value == "yes"


def test_update_ssh_setting_no_change_needed_commented(ssh_config_with_setting_commented):
    """Tests the update_ssh_setting with a commented setting that is already desired"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_setting_commented, "PasswordAuthentication", "no"
    )

    assert changed is True
    assert old_value == "no"
    assert new_value == "no"


def test_update_ssh_setting_modify_uncommented_setting(ssh_config_with_setting_commented):
    """Tests the update_ssh_setting with existing commented setting"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_setting_commented, "PasswordAuthentication", "yes"
    )

    assert changed is True
    assert old_value == "no"
    assert new_value == "yes"

    value, line_num, is_commented = get_current_ssh_setting(
        ssh_config_with_setting_commented, "PasswordAuthentication"
    )
    assert value == "yes"
    assert is_commented is False


def test_update_ssh_setting_add_new_setting(ssh_config_with_setting_active):
    """Tests adding a completely new setting"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_setting_active, "Port", "2222"
    )

    assert changed is True
    assert old_value is None
    assert new_value == "2222"


def test_update_ssh_setting_insertion_near_auth_settings(ssh_config_with_auth_settings):
    """Tests that new auth settings are inserted near existing auth settings"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_auth_settings, "ChallengeResponseAuthentication", "no"
    )
    
    assert changed is True
    assert old_value is None
    assert new_value == "no"
    
    # Read the file to check insertion location
    with open(ssh_config_with_auth_settings, 'r') as f:
        lines = f.readlines()
    
    # Find where the new setting was inserted
    new_setting_line = None
    for i, line in enumerate(lines):
        if "ChallengeResponseAuthentication no" in line:
            new_setting_line = i
            break
    
    assert new_setting_line is not None
    
    assert new_setting_line < len(lines) - 1


def test_update_ssh_setting_file_read_error(tmp_path):
    """Tests handling of file read errors"""
    nonexistent_file = tmp_path / "nonexistent.conf"
    
    with pytest.raises(Exception) as exc_info:
        update_ssh_setting(str(nonexistent_file), "ChallengeResponseAuthentication", "no")
    
    assert "Cannot read config file" in str(exc_info.value)
    

def test_update_ssh_setting_file_write_error(ssh_config_with_setting_active):
    """Tests handling of file write errors"""
    current_mode = os.stat(ssh_config_with_setting_active).st_mode
    os.chmod(ssh_config_with_setting_active, 0o400)

    try:
        with pytest.raises(Exception) as exc_info:
            changed, old_value, new_value = update_ssh_setting(
                ssh_config_with_setting_active, "ChallengeResponseAuthentication", "no"
            )
    finally:
        os.chmod(ssh_config_with_setting_active, current_mode)


def test_update_ssh_setting_case_insensitive(ssh_config_with_setting_active):
    """Tests that setting names are case insensitive"""
    changed, old_value, new_value = update_ssh_setting(
        ssh_config_with_setting_active, "x11forwarding", "no"
    )

    assert changed is True
    assert old_value == "yes"
    assert new_value == "no"

    value, line_num, is_commented = get_current_ssh_setting(
        ssh_config_with_setting_active, "X11Forwarding"
    )
    assert value == "no"


@patch('ansible.module_utils.basic.AnsibleModule')
def test_successful_restart(mock_ansible_module):
    """Test successful service restart"""
    mock_module = MagicMock()
    mock_module.run_command.return_value = (0, "", "")
    
    success, error_msg = restart_ssh_service(mock_module, 'sshd')
    
    assert success is True
    assert error_msg == ""
    mock_module.run_command.assert_called_once_with(['systemctl', 'restart', 'sshd'])

