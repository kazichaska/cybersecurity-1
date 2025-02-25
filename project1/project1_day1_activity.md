**Project Overview:**

In this project, you will play the role of a security professional tasked with hardening a Linux server owned by The Baker Street Corporation (BSC). The BSC has confidential data on their server and they need you to confirm that their system is properly configured to protect them from security breaches. If you determine any security issues, they also want you to make the necessary updates.

**Today's Focus:**

Today’s focus is on the BSC’s Linux server’s users, groups, files, and directories. You will be completing 5 steps:

1. Pre-hardening steps: System inventory and backup
2. Auditing users and groups
3. Updating and enforcing password policies
4. Updating and enforcing sudo permissions
5. Validating and updating permissions on files and directories

As you progress through the project, use the following Checklist and Summary Report to update your progress, document your commands, and add screenshots. Note that on the third day of the project, you will reuse your commands to design a script.

**Resources:**

- [Linux System Hardening: Top 10 Security Tips](https://tuxcare.com/blog/linux-system-hardening-top-10-security-tips/)
- [Linux Hardening: Secure Server Checklist](https://www.pluralsight.com/blog/it-ops/linux-hardening-secure-server-checklist)

**Instructions:**

### Day 1 Setup:

To start and access the lab, from Canvas select the weblab. 

Open your terminal, and run the following 3 commands:

1. To download the container: 
    ```bash
    sudo docker pull cyberxsecurity/container_project1_v4:latest
    ```

2. To start the container: 
    ```bash
    sudo docker run -d --hostname=Baker_Street_Linux_Server --network=host --name project1_v4 cyberxsecurity/container_project1_v4:latest
    ```

3. To connect to the container: 
    ```bash
    sudo docker exec -it project1_v4 /bin/bash
    ```

This will install, configure, and connect you to your lab. Note that this process may take between 5 - 10 minutes to complete!

See below for a screenshot of a successful installation and login.

---

**Note:** If you exit the lab, to return to the lab, run command number 3 from above to reconnect:
```bash
docker exec -it project1_v4 /bin/bash
```

---

### Part 1: Pre-Hardening Steps

In Part 1, before you start hardening the Linux Server, it is imperative that you document details about the operating system you are hardening and create a backup of the important files on the OS in case there is an issue during the hardening process. You will need to research any commands you aren’t familiar with.

Complete the following:
- Collect and document the following information on the summary report. Be sure to research the commands to complete these tasks!
    - HostName
    - OS version
    - Memory information
    - Uptime information

- Now backup the OS with the following command (note the directories being excluded):
    ```bash
    sudo tar -cvpzf /baker_street_backup.tar.gz --exclude=/baker_street_backup.tar.gz --exclude=/proc --exclude=/tmp --exclude=/mnt --exclude=/sys --exclude=/dev --exclude=/run /
    ```
- Be sure to note on your checklist what you have completed.
- Don’t forget to add screenshots!

### Part 2: Auditing Users and Groups

In Part 2, you are tasked with auditing BSC’s employees to make sure all of the correct users and groups have the minimum required access to do their work.

**Current Staff List and Position Updates:**

| Employee Name | Employment Status   |
|---------------|---------------------|
| sherlock      | Employed            |
| watson        | Employed            |
| mycroft       | Employed            |
| moriarty      | On temporary leave  |
| lestrade      | Terminated          |
| irene         | Terminated          |
| mrs_hudson    | On temporary leave  |
| mary          | Terminated          |
| gregson       | Terminated          |
| toby          | Employed            |
| adler         | Employed            |

Complete the following:
- Remove all staff who have been terminated. Be sure to remove all home directories and files.
- Lock all user accounts of staff on temporary leave.
- Unlock any users who are employed.
- Move all the employees who were in the marketing department to a new group called research. Create this group if it doesn't exist.
- Remove the marketing group as the marketing department was closed this year.
- Be sure to note on your checklist what you have completed.
- Don’t forget to add in your screenshots.

### Part 3: Updating and Enforcing Password Policies

In Part 3, you are tasked with validating the security of the passwords of BSC’s employees. Additionally, you will update the minimum complexity and force users to update their passwords on their next login.

Complete the following:
- Update the password requirements for all users to have:
    - Minimum 8 characters
    - At least one special character
    - Allow 2 retries
    - At least one uppercase character

To make this update:
- Edit the following file: `/etc/pam.d/common-password`
- Add settings to the following line:
    ```bash
    password requisite pam_pwquality.so
    ```
    Here are the available settings:
    - `minlen`: Minimum length of the password.
    - `dcredit`: Number of digits required (negative value means at least that many).
    - `ucredit`: Number of uppercase characters required (negative value means at least that many).
    - `lcredit`: Number of lowercase characters required (negative value means at least that many).
    - `ocredit`: Number of special characters required (negative value means at least that many).
    - `retry`: Number of times to retry if the user enters a bad password.

Here is an example line if the minimum length was 12, and number of retries is 3:
```bash
password requisite pam_pwquality.so retry=3 minlen=12
```
- Be sure to note on your checklist what you have completed.
- Don’t forget to add in screenshots!

### Part 4: Updating and Enforcing sudo Permissions

In Part 4, you are tasked with validating and updating the sudo file. BSC only wants a small group to be able to use sudo, and for those who have sudo, the only privileges they should have are to complete very specific tasks.

Complete the following:
- The only employee who should have full sudo privileges is Sherlock. Remove all other full privileged users.
- Watson and Mycroft should only have sudo privileges to run a script located here:
    ```bash
    /var/log/logcleanup.sh
    ```
- All employees who belong to the research group should have sudo privileges to run the following script:
    ```bash
    /tmp/scripts/research_script.sh
    ```
- Be sure to note on your checklist what you have completed.
- Don’t forget to add in your screenshots!

### Part 5: Validating and Updating Permissions on Files and Directories

In Part 5, you are tasked with validating and updating any files and directories that have weak security permissions.

Complete the following:
- In every user’s home directory, there should be no files that have any world permissions to read, write, or execute. Find any of them and update to remove the world permissions. For example:
    ```bash
    find /home -type f -perm /o=rwx -exec chmod o-rwx {} \;
    ```

- Find the following files and make the associated updates:
    - Engineering scripts (scripts with the word ‘engineering’ in the filename): Only members of the engineering group can view, edit, or execute. For example:
        ```bash
        chgrp engineering /path/to/engineering_script.sh
        chmod 770 /path/to/engineering_script.sh
        ```

    - Research scripts: Only members of the research group can view, edit, or execute. For example:
        ```bash
        chgrp research /path/to/research_script.sh
        chmod 770 /path/to/research_script.sh
        ```

    - Finance scripts: Only members of the finance group can view, edit, or execute. For example:
        ```bash
        chgrp finance /path/to/finance_script.sh
        chmod 770 /path/to/finance_script.sh
        ```

- Some employees may leave files with hidden passwords. Find those files and remove them as no employee should have their passwords stored on the server. For example:
    ```bash
    find /home -name "*password*" -type f -exec rm -f {} \;
    ```

- Exit the lab by entering:
    ```bash
    exit
    ```

- Be sure to note on your checklist what you have completed.
- Don’t forget to add in your screenshots!



Google docs link - https://docs.google.com/document/d/1fkehYvzbxKXPO0DSXp3AinbKAPDCkQz1WbQT95RD3Ts/edit?tab=t.0

