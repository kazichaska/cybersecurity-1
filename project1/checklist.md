# Project 1 Checklist

1. OS backup
2. Auditing users and groups
3. Updating and enforcing password policies
4. Updating and enforcing sudo permissions
5. Validating and updating permissions on files and directories
6. Optional: Updating password hashing configuration
7. Auditing and securing SSH
8. Reviewing and updating system packages
9. Disabling unnecessary services
10. Enabling and configuring logging
11. Scripts created
12. Scripts scheduled with cron

## Steps and Examples

### 1. OS backup
- **Step**: Use a backup tool to create a full system backup.
- **Example**: `tar -cvpzf /backup/backup.tar.gz --exclude=/backup /`

### 2. Auditing users and groups
- **Step**: List all users and groups and review their permissions.
- **Example**: `cat /etc/passwd` and `cat /etc/group`

### 3. Updating and enforcing password policies
- **Step**: Modify `/etc/login.defs` and `/etc/pam.d/common-password` to enforce strong passwords.
- **Example**: Set `PASS_MAX_DAYS 90` in `/etc/login.defs`

### 4. Updating and enforcing sudo permissions
- **Step**: Edit the sudoers file to restrict sudo access.
- **Example**: Use `visudo` to add `username ALL=(ALL) ALL`

### 5. Validating and updating permissions on files and directories
- **Step**: Check and modify file and directory permissions.
- **Example**: `chmod 644 /path/to/file` and `chmod 755 /path/to/directory`

### 6. Optional: Updating password hashing configuration
- **Step**: Update the password hashing algorithm in `/etc/pam.d/common-password`.
- **Example**: Use `pam_unix.so sha512`

### 7. Auditing and securing SSH
- **Step**: Review and update SSH configuration in `/etc/ssh/sshd_config`.
- **Example**: Set `PermitRootLogin no` and `PasswordAuthentication no`

### 8. Reviewing and updating system packages
- **Step**: Update all installed packages to their latest versions.
- **Example**: `sudo apt-get update && sudo apt-get upgrade`

### 9. Disabling unnecessary services
- **Step**: Identify and disable services that are not needed.
- **Example**: `sudo systemctl disable service_name`

### 10. Enabling and configuring logging
- **Step**: Ensure logging is enabled and properly configured.
- **Example**: Edit `/etc/rsyslog.conf` to configure log levels and destinations.

### 11. Scripts created
- **Step**: Write scripts to automate tasks.
- **Example**: Create a backup script `backup.sh` with `#!/bin/bash rsync -a /source /destination`

### 12. Scripts scheduled with cron
- **Step**: Schedule scripts to run at specified times using cron.
- **Example**: Add `0 2 * * * /path/to/backup.sh` to `crontab -e`