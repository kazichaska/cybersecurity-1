#!/bin/bash

# Variable for the report output file, choose a NEW output file name
REPORT_FILE="/scripts/hardening_report2.txt"

# Output the sshd configuration file
echo "Gathering details from sshd configuration file"
# Placeholder for command to get the sshd configuration file

echo "sshd configuration file:$(/etc/ssh/sshd_config)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE

# Update packages and services
Echo “Updating packages and services”

# Placeholder for command to update packages

apt-get update -y


# Placeholder for command to upgrade packages

apt-get upgrade -y

echo "Packages have been updated and upgraded" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Placeholder for command to list all installed packages

echo "Installed Packages:$(apt list --installed)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


echo “Printing out logging configuration data”

# Placeholder for command to display logging data

echo "journald.conf file data: $(cat /etc/systemd/journald.conf)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE

# Placeholder for command to display logrotate data

echo "logrotate.conf file data:$(cat /etc/logrotate.conf)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE

echo "Script execution completed. Check $REPORT_FILE for details."

