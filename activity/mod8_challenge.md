```
Instructions
Follow the instructions to work through the four phases of the network assessment. As you work, take note of:
The steps and commands used to complete the tasks
Any network vulnerabilities discovered
Any findings associated with a hacker
Recommended mitigation strategy
The OSI layer(s) your findings involve
You will use your notes to answer the questions in this quiz.
```

# RockStar Corp Server List

| IP Address       | Location       | Server Type               |
|------------------|----------------|---------------------------|
| 12.205.151.91    | New York       | Database Server           |
| 15.199.151.91    | New York       | Web Server 1              |
| 15.199.158.91    | New York       | Web Server 2              |
| 15.199.141.91    | New York       | Web Server 3              |
| 15.199.131.91    | New York       | Application Server 1      |
| 15.199.121.91    | New York       | Application Server 2      |
| 15.199.111.91    | Chicago        | Database Server           |
| 15.199.100.91    | Chicago        | Web Server 1              |
| 15.199.99.91     | Chicago        | Web Server 2              |
| 15.199.98.91     | Chicago        | Web Server 3              |
| 15.199.97.91     | Chicago        | Application Server 1      |
| 15.199.96.91     | Chicago        | Application Server 2      |
| 15.199.95.91     | Hollywood      | Database Server           |
| 15.199.94.91     | Hollywood      | Web Server 1              |
| 203.0.113.32     | Hollywood      | Web Server 2              |
| 161.35.96.20     | Hollywood      | Application Server 1      |
| 192.0.2.0        | Hollywood      | Application Server 2      |
| 192.0.2.16       | Miami          | Database Server           |
| 198.51.100.0     | Miami          | Web Server 1              |
| 198.51.100.16    | Miami          | Web Server 2              |
| 198.51.100.32    | Miami          | Web Server 3              |
| 203.0.113.0      | Miami          | Application Server        |
| 203.0.113.16     | Miami          | Database Server           |


for Hollywood server - 161.35.96.20 is replying
following request timed out
ping 15.199.95.91
ping 15.199.94.91
ping 203.0.113.32
ping 192.0.2.0

ICMP - layer 3 network

nmap -sS 161.35.96.20
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-06 17:18 CST
Nmap scan report for 161.35.96.20
Host is up (0.054s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE
22/tcp  open     ssh
25/tcp  filtered smtp
135/tcp filtered msrpc
139/tcp filtered netbios-ssn
445/tcp filtered microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.25 seconds

**OSI (Open Systems Interconnection) model**:

| **Port/Service**      | **Protocol**         | **OSI Layer(s)**                  | **Explanation**                                                                                   |
|-----------------------|----------------------|-----------------------------------|---------------------------------------------------------------------------------------------------|
| **22/tcp (SSH)**      | Secure Shell (SSH)   | **Layer 7 (Application)**         | SSH operates at the Application layer, enabling secure remote login and command execution.        |
| **25/tcp (SMTP)**     | Simple Mail Transfer Protocol (SMTP) | **Layer 7 (Application)**         | SMTP is used for email transmission between servers, functioning at the Application layer.        |
| **135/tcp (MSRPC)**   | Microsoft RPC (MSRPC) | **Layer 5 (Session) & Layer 7 (Application)** | Manages remote procedure calls, establishing sessions between applications across networks.       |
| **139/tcp (NetBIOS-SSN)** | NetBIOS Session Service | **Layer 5 (Session) & Layer 6 (Presentation)** | Facilitates file and printer sharing over networks using session services in Windows environments. |
| **445/tcp (Microsoft-DS)** | SMB over TCP (Direct Hosting) | **Layer 6 (Presentation) & Layer 7 (Application)** | Used for file sharing and network resource access without relying on NetBIOS, directly over TCP/IP. |

### 🔑 **Quick OSI Layer Breakdown:**
- **Layer 7 (Application):** User-facing protocols (SSH, SMTP, SMB).  
- **Layer 6 (Presentation):** Data formatting, encryption (SMB, NetBIOS).  
- **Layer 5 (Session):** Establishes, manages, and terminates connections (MSRPC, NetBIOS).  
- **Layer 4 (Transport):** Underlying TCP/UDP transport (all services rely on TCP here).  

```
sysadmin@ip-10-0-1-222:~$ sudo nmap -sS 161.35.96.20
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-06 23:21 UTC
Nmap scan report for 161.35.96.20
Host is up (0.0073s latency).
Not shown: 998 closed ports
PORT   STATE    SERVICE
22/tcp open     ssh
25/tcp filtered smtp
```

```
Nmap done: 1 IP address (1 host up) scanned in 14.39 seconds
sysadmin@ip-10-0-1-222:~$ ssh jimi@161.35.96.20
The authenticity of host '161.35.96.20 (161.35.96.20)' can't be established.
ECDSA key fingerprint is SHA256:wBJ5MSfBLi1YXiVEnzIyzE0+fE46NbmfUmBoZczVyAU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '161.35.96.20' (ECDSA) to the list of known hosts.
jimi@161.35.96.20's password: 
Linux gtclass-1578758377314-s-1vcpu-1gb-nyc1-01 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u5 (2019-08-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Feb  6 20:29:23 2025 from 54.219.166.217
Could not chdir to home directory /home/jimi: No such file or directory
$ whoami
jimi
$ 
```

```
jimi@gtclass-1578758377314-s-1vcpu-1gb-nyc1-01:/$ cat /etc/hosts
# Your system has configured 'manage_etc_hosts' as True.
# As a result, if you wish for changes to this file to persist
# then you will need to either
# a.) make changes to the master file in /etc/cloud/templates/hosts.tmpl
# b.) change or remove the value of 'manage_etc_hosts' in
#     /etc/cloud/cloud.cfg or cloud-config from user-data
#
127.0.1.1 gtclass-1578758377314-s-1vcpu-1gb-nyc1-01.localdomain gtclass-1578758377314-s-1vcpu-1gb-nyc1-01
127.0.0.1 localhost
98.137.246.8 rollingstone.com

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

jimi@gtclass-1578758377314-s-1vcpu-1gb-nyc1-01:/$ 
```

```
jimi@gtclass-1578758377314-s-1vcpu-1gb-nyc1-01:/$ cat /etc/packetcaptureinfo.txt 
My Captured Packets are Here:

https://drive.google.com/file/d/1ic-CFFGrbruloYrWaw3PvT71elTkh3eF/view?usp=sharing

jimi@gtclass-1578758377314-s-1vcpu-1gb-nyc1-01:/$ 

```

```
nslookup 98.137.246.8
Server:         2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:        2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
8.246.137.98.in-addr.arpa       name = unknown.yahoo.com.

Authoritative answers can be found from:
```


here is the detail from capture file

```
Frame 16: 1876 bytes on wire (15008 bits), 1876 bytes captured (15008 bits) on interface any, id 0
    Section number: 1
    Interface id: 0 (any)
        Interface name: any
    Encapsulation type: Linux cooked-mode capture v1 (25)
    Arrival Time: Aug 15, 2019 13:01:46.121459902 UTC
    UTC Arrival Time: Aug 15, 2019 13:01:46.121459902 UTC
    Epoch Arrival Time: 1565874106.121459902
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 104.542662506 seconds]
    [Time delta from previous displayed frame: 104.542662506 seconds]
    [Time since reference or first frame: 176825119.780586902 seconds]
    Frame Number: 16
    Frame Length: 1876 bytes (15008 bits)
    Capture Length: 1876 bytes (15008 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: sll:ethertype:ip:tcp:http:urlencoded-form]
    [Coloring Rule Name: HTTP]
    [Coloring Rule String: http || tcp.port == 80 || http2]
Linux cooked capture v1
    Packet type: Sent by us (4)
    Link-layer address type: Ethernet (1)
    Link-layer address length: 6
    Source: PCSSystemtec_f8:42:a7 (08:00:27:f8:42:a7)
    Unused: b801
    Protocol: IPv4 (0x0800)
Internet Protocol Version 4, Src: ip-10-0-2-15.ec2.internal (10.0.2.15), Dst: 104.18.126.89 (104.18.126.89)
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 1860
    Identification: 0x504a (20554)
    010. .... = Flags: 0x2, Don't fragment
        0... .... = Reserved bit: Not set
        .1.. .... = Don't fragment: Set
        ..0. .... = More fragments: Not set
    ...0 0000 0000 0000 = Fragment Offset: 0
    Time to Live: 64
    Protocol: TCP (6)
    Header Checksum: 0xf0ef [validation disabled]
    [Header checksum status: Unverified]
    Source Address: ip-10-0-2-15.ec2.internal (10.0.2.15)
    Destination Address: 104.18.126.89 (104.18.126.89)
Transmission Control Protocol, Src Port: 33546, Dst Port: 80, Seq: 1, Ack: 1, Len: 1820
    Source Port: 33546
    Destination Port: 80
    [Stream index: 7]
    [Conversation completeness: Incomplete (8)]
        ..0. .... = RST: Absent
        ...0 .... = FIN: Absent
        .... 1... = Data: Present
        .... .0.. = ACK: Absent
        .... ..0. = SYN-ACK: Absent
        .... ...0 = SYN: Absent
        [Completeness Flags: ··D···]
    [TCP Segment Len: 1820]
    Sequence Number: 1    (relative sequence number)
    Sequence Number (raw): 162855424
    [Next Sequence Number: 1821    (relative sequence number)]
    Acknowledgment Number: 1    (relative ack number)
    Acknowledgment number (raw): 25216002
    0101 .... = Header Length: 20 bytes (5)
    Flags: 0x018 (PSH, ACK)
        000. .... .... = Reserved: Not set
        ...0 .... .... = Accurate ECN: Not set
        .... 0... .... = Congestion Window Reduced: Not set
        .... .0.. .... = ECN-Echo: Not set
        .... ..0. .... = Urgent: Not set
        .... ...1 .... = Acknowledgment: Set
        .... .... 1... = Push: Set
        .... .... .0.. = Reset: Not set
        .... .... ..0. = Syn: Not set
        .... .... ...0 = Fin: Not set
        [TCP Flags: ·······AP···]
    Window: 29200
    [Calculated window size: 29200]
    [Window size scaling factor: -1 (unknown)]
    Checksum: 0xf9b0 [unverified]
    [Checksum Status: Unverified]
    Urgent Pointer: 0
    [Timestamps]
        [Time since first frame in this TCP stream: 0.000000000 seconds]
        [Time since previous frame in this TCP stream: 0.000000000 seconds]
    [SEQ/ACK analysis]
        [Bytes in flight: 1820]
        [Bytes sent since last PSH flag: 1820]
    TCP payload (1820 bytes)
Hypertext Transfer Protocol
    POST /formservice/en/3f64542cb2e3439c9bd01649ce5595ad/6150f4b54616438dbb01eb877296d534/c3a179f3630a440a96196bead53b76fa/I660593e583e747f1a91a77ad0d3195e3/ HTTP/1.1\r\n
        [Expert Info (Chat/Sequence): POST /formservice/en/3f64542cb2e3439c9bd01649ce5595ad/6150f4b54616438dbb01eb877296d534/c3a179f3630a440a96196bead53b76fa/I660593e583e747f1a91a77ad0d3195e3/ HTTP/1.1\r\n]
            [POST /formservice/en/3f64542cb2e3439c9bd01649ce5595ad/6150f4b54616438dbb01eb877296d534/c3a179f3630a440a96196bead53b76fa/I660593e583e747f1a91a77ad0d3195e3/ HTTP/1.1\r\n]
            [Severity level: Chat]
            [Group: Sequence]
        Request Method: POST
        Request URI: /formservice/en/3f64542cb2e3439c9bd01649ce5595ad/6150f4b54616438dbb01eb877296d534/c3a179f3630a440a96196bead53b76fa/I660593e583e747f1a91a77ad0d3195e3/
        Request Version: HTTP/1.1
    Host: forms.yola.com\r\n
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n
    Accept-Language: en-US,en;q=0.5\r\n
    Accept-Encoding: gzip, deflate\r\n
    Referer: http://www.gottheblues.yolasite.com/contact-us.php\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    Content-Length: 1163\r\n
        [Content length: 1163]
    Cookie: __cfduid=d8276a0af391153d2babc8fc7c64175b01565873955\r\n
        Cookie pair: __cfduid=d8276a0af391153d2babc8fc7c64175b01565873955
    Connection: keep-alive\r\n
    Upgrade-Insecure-Requests: 1\r\n
    \r\n
    [Full request URI: http://forms.yola.com/formservice/en/3f64542cb2e3439c9bd01649ce5595ad/6150f4b54616438dbb01eb877296d534/c3a179f3630a440a96196bead53b76fa/I660593e583e747f1a91a77ad0d3195e3/]
    [HTTP request 1/1]
    [Response in frame: 17]
    File Data: 1163 bytes
HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "0<text>" = "Mr Hacker"
        Key: 0<text>
        Value: Mr Hacker
    Form item: "0<label>" = "Name"
        Key: 0<label>
        Value: Name
    Form item: "1<text>" = "Hacker@rockstarcorp.com"
        Key: 1<text>
        Value: Hacker@rockstarcorp.com
    Form item: "1<label>" = "Email"
        Key: 1<label>
        Value: Email
    Form item: "2<text>" = ""
        Key: 2<text>
        Value: 
    Form item: "2<label>" = "Phone"
        Key: 2<label>
        Value: Phone
    Form item: "3<textarea>" = "Hi Got The Blues Corp!  This is a hacker that works at Rock Star Corp.  Rock Star has left port 22, SSH open if you want to hack in.  For 1 Milliion Dollars I will provide you the user and password!"
        Key: 3<textarea>
        Value: Hi Got The Blues Corp!  This is a hacker that works at Rock Star Corp.  Rock Star has left port 22, SSH open if you want to hack in.  For 1 Milliion Dollars I will provide you the user and password!
    Form item: "3<label>" = "Message"
        Key: 3<label>
        Value: Message
    Form item: "redirect" = "http://www.gottheblues.yolasite.com/contact-us.php?formI660593e583e747f1a91a77ad0d3195e3Posted=true"
        Key: redirect
        Value: http://www.gottheblues.yolasite.com/contact-us.php?formI660593e583e747f1a91a77ad0d3195e3Posted=true
    Form item: "locale" = "en"
        Key: locale
        Value: en
    Form item: "redirect_fail" = "http://www.gottheblues.yolasite.com/contact-us.php?formI660593e583e747f1a91a77ad0d3195e3Posted=false"
        Key: redirect_fail
        Value: http://www.gottheblues.yolasite.com/contact-us.php?formI660593e583e747f1a91a77ad0d3195e3Posted=false
    Form item: "form_name" = ""
        Key: form_name
        Value: 
    Form item: "site_name" = "GottheBlues"
        Key: site_name
        Value: GottheBlues
    Form item: "wl_site" = "0"
        Key: wl_site
        Value: 0
    Form item: "destination" = "DQvFymnIKN6oNo284nIPnKyVFSVKDX7O5wpnyGVYZ_YSkg==:3gjpzwPaByJLFcA2ouelFsQG6ZzGkhh31_Gl2mb5PGk="
        Key: destination
        Value: DQvFymnIKN6oNo284nIPnKyVFSVKDX7O5wpnyGVYZ_YSkg==:3gjpzwPaByJLFcA2ouelFsQG6ZzGkhh31_Gl2mb5PGk=
     [truncated]Form item: "g-recaptcha-response" = "03AOLTBLQA9oZg2Lh3adsE0c7OrYkMw1hwPof8xGnYIsZh8cz5TtLwl8uDMZuVOls6duzyYq2MTzsVHYzKda77dqzzNUwpa6F5Tu6b9875yKU1wZHpfOQmV8D7OTcx2rnGD6I8s-6qvyDAjCuS6vA78-iNLNUtWZXFJwleNj3hPquVMu-yzcSOX60Y-deZ
        Key: g-recaptcha-response
        Value [truncated]: 03AOLTBLQA9oZg2Lh3adsE0c7OrYkMw1hwPof8xGnYIsZh8cz5TtLwl8uDMZuVOls6duzyYq2MTzsVHYzKda77dqzzNUwpa6F5Tu6b9875yKU1wZHpfOQmV8D7OTcx2rnGD6I8s-6qvyDAjCuS6vA78-iNLNUtWZXFJwleNj3hPquVMu-yzcSOX60Y-deZC8zXn8hu4c6uW0-aWc711YdgRnK3yO

```

```
Sender MAC address: ip-192-168-47-200.ec2.internal (00:0c:29:1d:b3:b1)

Correct, they are creating a spoof record to direct the traffic intended for 192.168.47.200 over to their device.
```