Part 1: Scripting your hardening tasks

Over the last 2 class days, you have done great work hardening and auditing BSC’s environment. While you have protected BSC’s Linux server, you have done each part, one step at a time. In Part 1 of today’s activities, you will build out 2 scripts to automate many of the tasks you completed over the last two days. The first script will be for the first day’s tasks, and the second script will cover the second day’s tasks. Additionally, you have been provided with script templates to guide you through the script development process. Once you have built out your scripts, test them out to confirm there are no errors.

Complete the following steps:

### Script 1:
1. View and copy the following script 1 template.
2. Update the script everywhere you see placeholders in red. Be sure to remove all the placeholders!
3. Copy the script into a file called `hardening_script1.sh`.
4. Update the permissions of the script using the command:
    ```bash
    chmod +x hardening_script1.sh
    ```
5. Run the script to validate there are no errors:
    ```bash
    ./hardening_script1.sh
    ```

### Script 2:
1. View and copy the following script 2 template.
2. Update the script everywhere you see placeholders in red. Be sure to remove all the placeholders!
3. Copy the script into a file called `hardening_script2.sh`.
4. Update the permissions of the script using the command:
    ```bash
    chmod +x hardening_script2.sh
    ```
5. Run the script to validate there are no errors:
    ```bash
    ./hardening_script2.sh
    ```

Be sure to note on your checklist what you have completed.


Part 2: Scheduling your hardening scripts

In Part 2 of today’s activity, you will use cron to schedule the 2 scripts you just created.

Complete the following steps:

1. Using cron, schedule script 1 to run once a month on the first of the month.
2. Using cron, schedule script 2 to run once a week every Monday.

Be sure to note on your checklist what you have completed.

### Scheduling Script 1:
1. Open the crontab editor:
    ```bash
    crontab -e
    ```
2. Add the following line to schedule script 1:
    ```bash
    0 0 1 * * /path/to/hardening_script1.sh
    ```

### Scheduling Script 2:
1. Open the crontab editor:
    ```bash
    crontab -e
    ```
2. Add the following line to schedule script 2:
    ```bash
    0 0 * * 1 /path/to/hardening_script2.sh
    ```

Part 3: Completing your summary report

For the final activity of your project, you are tasked with completing your summary report.

Complete the following steps:

1. From your summary report, check off all completed tasks.
2. Summarize your findings of your security concerns at the conclusion of the report.
3. Submit your project report in Bootcampspot.

Be sure to note on your checklist what you have completed.