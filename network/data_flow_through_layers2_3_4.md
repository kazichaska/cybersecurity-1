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

## Conclusion

Understanding these concepts is crucial for network and security professionals to effectively manage and secure network communications. Tools like Wireshark can provide valuable insights into network traffic and help diagnose issues at various layers of the OSI model.


