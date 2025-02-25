```
Project Objectives
By the end of today's class, you will:

Audit an organization's users and groups.
Update and enforce their password policies.
Update and enforce their sudo permissions.
Validate and update permissions on files and directories.

```

1. **Audit an organization's users and groups**
    - List all users: `cat /etc/passwd`
    - List all groups: `cat /etc/group`
    - Check user details: `id <username>`
    - Example: `id john`

2. **Update and enforce their password policies**
    - Edit the password policy file: `sudo nano /etc/login.defs`
    - Set password aging: `PASS_MAX_DAYS 90`
    - Example: `chage -M 90 john`

3. **Update and enforce their sudo permissions**
    - Edit the sudoers file: `sudo visudo`
    - Add user to sudoers: `john ALL=(ALL) ALL`
    - Example: `sudo usermod -aG sudo john`

4. **Validate and update permissions on files and directories**
    - Check file permissions: `ls -l <file>`
    - Change file permissions: `chmod 644 <file>`
    - Example: `chmod 755 /home/john`

```
Today’s focus is on the BSC’s Linux server’s users, groups, files, and directories. You will be completing 5 steps:


(1) Pre-hardening steps: System inventory and backup
(2) Auditing users and groups
(3) Updating and enforcing password policies
(4) Updating and enforcing sudo permissions
(5) Validating and updating permissions on files and directories.
```
## Pre-hardening steps: System inventory and backup

1. **System Inventory**
    - List installed packages: `dpkg --get-selections`
    - Check system information: `uname -a`
    - Example: `uname -r`

2. **System Backup**
    - Backup important files: `tar -cvzf backup.tar.gz /etc /home`
    - Verify backup: `tar -tvf backup.tar.gz`
    - Example: `tar -cvzf /backup/backup_$(date +%F).tar.gz /etc /home`

## Auditing users and groups

1. **List all users**
    - Command: `cat /etc/passwd`
    - Example: `cat /etc/passwd | grep '/bin/bash'`

2. **List all groups**
    - Command: `cat /etc/group`
    - Example: `cat /etc/group | grep 'sudo'`

3. **Check user details**
    - Command: `id <username>`
    - Example: `id john`

## Updating and enforcing password policies

1. **Edit the password policy file**
    - Command: `sudo nano /etc/login.defs`
    - Example: `sudo nano /etc/login.defs`

2. **Set password aging**
    - Command: `chage -M 90 <username>`
    - Example: `chage -M 90 john`

## Updating and enforcing sudo permissions

1. **Edit the sudoers file**
    - Command: `sudo visudo`
    - Example: `sudo visudo`

2. **Add user to sudoers**
    - Command: `usermod -aG sudo <username>`
    - Example: `usermod -aG sudo john`

## Validating and updating permissions on files and directories

1. **Check file permissions**
    - Command: `ls -l <file>`
    - Example: `ls -l /home/john`

2. **Change file permissions**
    - Command: `chmod 644 <file>`
    - Example: `chmod 755 /home/john`
```
```

