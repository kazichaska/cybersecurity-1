#!/bin/bash

# Variable for the report output file, choose an output file name
REPORT_FILE="/scripts/hardening_report1.txt"

# Output the hostname
echo "Gathering hostname..."
# Placeholder for command to get the hostname
echo "Hostname: $(`hostname`)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Output the OS version
echo "Gathering OS version..."
# Placeholder for command to get the OS version
echo "OS Version: $(uname -u)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Output memory information
echo "Gathering memory information..."
# Placeholder for command to get memory info
echo "Memory Information: $(`free -h`)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Output uptime information
echo "Gathering uptime information..."
# Placeholder for command to get uptime info
echo "Uptime Information: $(uptime)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Backup the OS
echo "Backing up the OS..."
# Placeholder for command to back up the OS

tar -czvf /tmp/backup_$(date +%Y%m%d_%H%M%S).tar.gz --exclude=/tmp --exclude=/proc --exclude=/dev --exclude=/sys --exclude=/run /

echo "OS backup completed." >> $REPORT_FILE
printf "\n" >> $REPORT_FILE



# Output the sudoers file to the report
echo "Gathering sudoers file..."
# Placeholder for command to output sudoers file
echo "Sudoers file:$(`cat /etc/sudoers`)" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Script to check for files with world permissions and update them
echo "Checking for files with world permissions..."

find /home -type f -perm -o=w -exec chmod o-w {} +

# Placeholder for command to find and update files with world permissions
echo "World permissions have been removed from any files found." >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Find specific files and update their permissions
echo "Updating permissions for specific scripts..."

# Engineering scripts - Only members of the engineering group
echo "Updating permissions for Engineering scripts."


# Placeholder for command to update permissions
find /home/ -type f -iname "*engineering*" -exec chown :engineering {} + -exec chmod 770 {} +

Here is the example command for the engineering group:   

find /home -iname '*engineering*' -exec chown :engineering {} +


echo "Permissions updated for Engineering scripts." >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Research scripts - Only members of the research group
echo "Updating permissions for Research scripts..."
# Placeholder for command to update permissions

find /home/ -type f -iname "*research*" -exec chown :finance {} + -exec chmod 770 {} +

echo "Permissions updated for Research scripts" >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


# Finance scripts - Only members of the finance group
echo "Updating permissions for Finance scripts"
# Placeholder for command to update permissions

find /home/ -type f -iname "*finance*" -exec chown :finance {} + -exec chmod 770 {} +

echo "Permissions updated for Finance scripts." >> $REPORT_FILE
printf "\n" >> $REPORT_FILE


echo "Script execution completed. Check $REPORT_FILE for details."


