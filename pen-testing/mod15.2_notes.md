
Phishing - `https://phishingquiz.withgoogle.com/` 

`Port 21 is open for 172.22.117.150`

Took screenshot from nmap/zenmap for 172.22.117.0/24 and shows one IP 172.22.117.100 with ports 22, 80, 5901, 6001 and 8080 open not 21

Password Guessing - `vpn into vpn.megacorpone.com` and guess passwords
`username: thudson password:thudson`
```
root@ip-10-0-1-231:/home/sysadmin# cat crack.txt 
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
msfadmin:$1$czKn4zfS$6c/n1V94al6Nt2LS7o5p30:18996:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14699:0:99999:7:::
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:14715:0:99999:7:::
tstark:$1$SI3.cmzw$agMjsOSBH1cZc/E8pahL..:19005:0:99999:7:::
root@ip-10-0-1-231:/home/sysadmin# 

```

`sudo nmap -sC -sV -A -O -p- IPADDRESS`  - aggressive scan. If it is too slow remove `-p-` from it