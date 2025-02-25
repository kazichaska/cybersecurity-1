## Hardening System Configuration

### 1. Audit and Secure SSH Settings
- **Disable root login**: Edit the `/etc/ssh/sshd_config` file and set `PermitRootLogin no`.
- **Change default port**: Modify the `Port` directive in `/etc/ssh/sshd_config` to a non-standard port.
- **Use key-based authentication**: Disable password authentication by setting `PasswordAuthentication no` in `/etc/ssh/sshd_config`.

### 2. Review and Update System Packages
- **Update package lists**: Run `sudo apt-get update` on Debian-based systems or `sudo yum check-update` on Red Hat-based systems.
- **Upgrade installed packages**: Use `sudo apt-get upgrade` or `sudo yum update` to install the latest versions of all packages.

### 3. Disable Unnecessary Services
- **List running services**: Use `systemctl list-units --type=service` to see all active services.
- **Disable a service**: Run `sudo systemctl disable <service_name>` to prevent a service from starting at boot.

### 4. Enable and Configure Logging
- **Install logging service**: Ensure `rsyslog` or a similar service is installed using `sudo apt-get install rsyslog`.
- **Configure log rotation**: Edit `/etc/logrotate.conf` to manage log file sizes and retention periods.
- **Review logs regularly**: Use `tail -f /var/log/syslog` to monitor system logs in real-time.



### 5. Configure SSH Security Settings
- **Disable empty passwords**: Edit the `/etc/ssh/sshd_config` file and set `PermitEmptyPasswords no`.
- **Disable root login**: Ensure `PermitRootLogin no` is set in `/etc/ssh/sshd_config`.
- **Restrict to port 22**: Set `Port 22` in `/etc/ssh/sshd_config` to use the default SSH port.
- **Enable SSH protocol 2**: Ensure `Protocol 2` is set in `/etc/ssh/sshd_config`.
- **Restart SSH service**: Apply the changes by running `sudo service ssh restart`.


### Part 2: Review, Update, and Add System Packages

In Part 2, you will be reviewing and updating your system packages. This is important because app developers often release patches to protect from security vulnerabilities. Having the latest version of your packages minimizes your security risks.

Complete the following:
- **Update package manager**: Run `sudo apt update` to ensure your package manager has the latest version of all packages.
- **Upgrade installed packages**: Run `sudo apt upgrade -y` to update all already installed packages to the latest versions.
- **List installed packages**: Create a file called `package_list.txt` containing all installed packages. Use `apt list --installed` to view installed packages.
- **Identify and remove insecure packages**: Check if `telnet` or `rsh-client` are installed. If they are, remove them using `sudo apt remove telnet rsh-client`.
- **Research security issues**: Document why `telnet` and `rsh-client` could introduce security issues.
- **Remove unnecessary dependencies**: Run `sudo apt autoremove -y` to remove all unnecessary dependencies of the removed packages.
- **Install additional security packages**: Add the following packages using `sudo apt install ufw lynis tripwire`.
    - Example: `sudo apt install ufw` to install Uncomplicated Firewall.
    - Example: `sudo apt install lynis` to install Lynis security auditing tool.
    - Example: `sudo apt install tripwire` to install Tripwire intrusion detection system.
- **Document hardening features**: Research and document the hardening features provided by `ufw`, `lynis`, and `tripwire`.
    - Example: `ufw` provides an easy-to-use interface for managing firewall rules.
    - Example: `lynis` performs an in-depth security scan of your system and provides recommendations.
    - Example: `tripwire` monitors and alerts on file system changes to detect unauthorized modifications.
- **Checklist**: Note on your checklist what you have completed.



### Part 3: Disabling Unnecessary Services

In Part 3, you will be reviewing and disabling any unnecessary services. This is important because having unnecessary services running increases your attack surface. Follow the steps below to identify and remove any unnecessary services.

Complete the following:
    (Hint: View Lesson 4.3 to assist with the commands.)
- **List all services**: Run the command `service --status-all` to list out all services. Output this into a file called `service_list.txt` using `service --status-all > service_list.txt`.
- **Identify specific services**: Check if any of the following services are running:
    - `mysql`
    - `samba`
- **Stop running services**: If any of the above services are running, stop them using `sudo service <service_name> stop`. For example, `sudo service mysql stop`.
- **Disable services**: Disable the services to prevent them from starting at boot using `sudo update-rc.d <service_name> disable`. For example, `sudo update-rc.d mysql disable`.
- **Remove services**: Remove the services if they are not needed using `sudo apt-get remove <service_name>`. For example, `sudo apt-get remove mysql-server`.
- **Checklist**: Note on your checklist what you have completed.

Example commands:
- `service --status-all > service_list.txt`
- `sudo service mysql stop`
- `sudo update-rc.d mysql disable`
- `sudo apt-get remove mysql-server`



### Part 4: Enabling and Configuring Logging

In Part 4, you will be configuring and checking logging settings on Baker Street’s Linux server. Logging is a crucial part of the hardening process as it can help identify security issues such as suspicious network activity, unauthorized access, or other anomalous activity.

Complete the following:
- **Access the journald.conf file**: Located at `/etc/systemd/journald.conf`.
- **Edit settings using nano**: Use `nano` to edit the following settings in the file. Be sure to uncomment the lines!
    - **Set `Storage=persistent`**: This setting will save the logs locally on the machine.
    - **Set `SystemMaxUse=300M`**: This setting configures the maximum disk space the logs can utilize.
- **Configure log rotation**: To prevent logs from taking up too much space, you will need to configure log rotation.
    - Use the following guide to assist: [logrotate manual](https://linux.die.net/man/8/logrotate).
    - **Edit the file**: `/etc/logrotate.conf` with the following settings:
        - Change the log rotation from weekly to daily.
        - Rotate out the logs after 7 days.
- **Save your changes**: Ensure all changes are saved.
- **Checklist**: Note on your checklist what you have completed.
