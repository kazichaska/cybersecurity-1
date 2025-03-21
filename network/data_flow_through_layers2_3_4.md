# Data Flow Through Layers 2, 3, and 4

## Introduction

- **Protocols**: Standardized rules that dictate how data is communicated.
- **Ports**: Assist with where the data is transmitted to and from, with respect to the server and client.
- **OSI Model**: The seven layers conceptualize how data is communicated across a network.
- **Wireshark**: A powerful utility for in-depth analysis of network packets.

## Lesson Overview

In this lesson, we will cover the following concepts:

### Enumeration

- **Definition**: The process of gathering data for a specific network.
- **Purpose**: Helps in identifying network resources, services, and potential vulnerabilities.
- **Example**: Using `nmap` to enumerate network devices.
  ```bash
  nmap -sP 192.168.1.0/24
  ```

### Layer 2: Data Link Protocol ARP

- **ARP (Address Resolution Protocol)**: Used to transfer network traffic within a local network.
- **Function**: Maps IP addresses to MAC addresses, allowing devices to communicate within the same network.
- **Example**: Viewing the ARP table on a Linux machine.
  ```bash
  arp -a
  ```

### Layer 3: Network Utilities

- **Ping**: Used to test the reachability of a host on an IP network and measure the round-trip time for messages.
  - **Example**: Pinging a website.
    ```bash
    ping www.google.com
    ```
- **Traceroute**: Used to trace the path that packets take from source to destination, helping diagnose network issues.
  - **Example**: Running traceroute to a website.
    ```bash
    traceroute www.google.com
    ```

### Layer 4: Transport Protocols

- **TCP (Transmission Control Protocol)**: Establishes a connection with a three-way handshake (SYN, SYN-ACK, ACK).
  - **Example**: Using `telnet` to test a TCP connection.
    ```bash
    telnet www.google.com 80
    ```
- **UDP (User Datagram Protocol)**: A connectionless protocol that sends data without establishing a connection.
  - **Example**: Using `nc` (netcat) to send a UDP packet.
    ```bash
    echo "test" | nc -u 192.168.1.1 12345
    ```

### SYN Scans

- **Definition**: A method used to determine the state of ports in a network.
- **Usage**: Both security professionals and attackers use SYN scans to identify open, closed, or filtered ports.
- **Example**: Performing a SYN scan with `nmap`.
  ```bash
  nmap -sS 192.168.1.1
  ```


```
nmap -Pn 184.73.212.55
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-13 21:14 CDT
Warning: File ./nmap-services exists, but Nmap is using /opt/homebrew/bin/../share/nmap/nmap-services for security and consistency reasons.  set NMAPDIR=. to give priority to files in your local directory (may affect the other data files too).
Nmap scan report for ec2-184-73-212-55.compute-1.amazonaws.com (184.73.212.55)
Host is up (0.052s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 49.14 seconds


nmap -Pn 13.236.118.229
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-13 21:16 CDT
Warning: File ./nmap-services exists, but Nmap is using /opt/homebrew/bin/../share/nmap/nmap-services for security and consistency reasons.  set NMAPDIR=. to give priority to files in your local directory (may affect the other data files too).
Nmap scan report for ec2-13-236-118-229.ap-southeast-2.compute.amazonaws.com (13.236.118.229)
Host is up (0.20s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  closed https
3389/tcp open   ms-wbt-server
5900/tcp closed vnc
5901/tcp closed vnc-1
5902/tcp closed vnc-2
5903/tcp closed vnc-3
5904/tcp closed ag-swim
8080/tcp closed http-proxy

Nmap done: 1 IP address (1 host up) scanned in 98.37 seconds


```

## Conclusion

Understanding these concepts is crucial for network and security professionals to effectively manage and secure network communications. Tools like Wireshark can provide valuable insights into network traffic and help diagnose issues at various layers of the OSI model.


