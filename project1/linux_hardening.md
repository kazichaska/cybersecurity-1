## Day 1: Initial Steps

To begin the process of hardening your Linux system, follow these initial steps:

1. **System Inventory and Backup**: Create a comprehensive inventory of your system and perform a full backup to ensure you can restore your system if needed.
    - Example: Use `rsync` to create backups, e.g., `rsync -a /source/directory /backup/directory`.

2. **Auditing Users and Groups**: Review and audit all user accounts and groups to ensure that only authorized users have access to the system.
    - Example: Use `cat /etc/passwd` and `cat /etc/group` to list all users and groups, and `userdel` to remove unauthorized users.

3. **Password Policies**: Implement strong password policies to enhance account security.
    - Example: Edit `/etc/login.defs` to set password aging policies, e.g., `PASS_MAX_DAYS 90` to require password changes every 90 days.

4. **sudo Permissions**: Restrict and audit `sudo` permissions to ensure that only trusted users have administrative access.
    - Example: Edit `/etc/sudoers` using `visudo` to specify which users can use `sudo`, e.g., `kaziislam ALL=(ALL) ALL` to grant `sudo` access to the user `kaziislam`.

5. **File and Directory Permissions**: Ensure that file and directory permissions are properly set to restrict access to authorized users only.
    - Example: Use `chmod` to set file permissions, e.g., `chmod 700 /home/username` to restrict access to the user's home directory.

By completing these steps on Day 1, you will establish a solid foundation for securing your Linux system.


# Linux Hardening

To enhance the security of a Linux system, consider the following hardening steps:

1. **Assure Correct Permissioning and System Access**: Ensure that file and directory permissions are properly set to restrict access to authorized users only.
    - Example: Use `chmod` to set file permissions, e.g., `chmod 600 /etc/ssh/sshd_config` to restrict access to the SSH configuration file.
2. **Remove Unnecessary Services, Processes, and Applications**: Disable or uninstall services, processes, and applications that are not needed to minimize potential attack vectors.
    - Example: Use `systemctl disable` to stop and disable unnecessary services, e.g., `systemctl disable telnet` to disable the Telnet service.
3. **Utilize Secure Configuration Options**: Configure system settings and applications with security best practices to reduce vulnerabilities.
    - Example: Edit `/etc/sysctl.conf` to enable IP spoofing protection, e.g., `net.ipv4.conf.all.rp_filter = 1`.
4. **Patch and Update Current Systems and Processes**: Regularly apply patches and updates to the operating system and software to protect against known security threats.
    - Example: Use package managers like `apt` or `yum` to update systems, e.g., `apt update && apt upgrade` for Debian-based systems.

By following these steps, you can significantly improve the security posture of your Linux system.



