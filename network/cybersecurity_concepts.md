```markdown
# Cybersecurity Concepts Explained

This document provides explanations for key cybersecurity and networking concepts. Use this as a reference for your studies and projects.

---

## **Subnetting**
Subnetting is the process of dividing a larger network into smaller, more manageable subnetworks (subnets). It helps improve network performance, security, and organization by reducing broadcast traffic and isolating network segments.

- **Example**: Dividing a network with IP `192.168.1.0/24` into smaller subnets like `192.168.1.0/26`.

---

## **CIDR (Classless Inter-Domain Routing)**
CIDR is a method for allocating IP addresses and routing Internet Protocol packets. It replaces the older classful network addressing system and allows for more efficient use of IP addresses.

- **Notation**: Written as `IP_address/Prefix_length` (e.g., `192.168.1.0/24`).
- **Purpose**: Reduces IP address waste and simplifies routing.

---

## **IP Addresses**
An IP (Internet Protocol) address is a unique identifier assigned to devices on a network. It allows devices to communicate with each other.

- **IPv4**: 32-bit address (e.g., `192.168.1.1`).
- **IPv6**: 128-bit address (e.g., `2001:0db8:85a3::8a2e:0370:7334`).

---

## **Ping**
Ping is a network utility used to test the reachability of a device on a network. It sends ICMP (Internet Control Message Protocol) echo requests and waits for replies.

- **Command**: `ping <IP_address>`.
- **Use Case**: Troubleshooting network connectivity.

---

## **OSI Model and Its Layers**
The OSI (Open Systems Interconnection) model is a conceptual framework used to understand network interactions. It consists of 7 layers:

1. **Physical Layer**: Transmits raw bits over a physical medium (e.g., cables).
2. **Data Link Layer**: Handles node-to-node data transfer (e.g., MAC addresses).
3. **Network Layer**: Manages device addressing and routing (e.g., IP addresses).
4. **Transport Layer**: Ensures reliable data delivery (e.g., TCP, UDP).
5. **Session Layer**: Manages connections between applications.
6. **Presentation Layer**: Translates data into a readable format (e.g., encryption).
7. **Application Layer**: Provides network services to applications (e.g., HTTP, FTP).

---

## **Protocols**
Protocols are rules and standards that govern communication between devices on a network.

- **Examples**:
  - **TCP**: Ensures reliable, ordered data delivery.
  - **UDP**: Faster but less reliable than TCP.
  - **HTTP/HTTPS**: Used for web communication.
  - **FTP**: Used for file transfers.

---

## **Ports**
Ports are virtual endpoints for communication in a network. They allow multiple services to run on a single device.

- **Well-Known Ports**: 0–1023 (e.g., HTTP on port 80, HTTPS on port 443).
- **Registered Ports**: 1024–49151.
- **Dynamic Ports**: 49152–65535.

---

## **Wireshark**
Wireshark is a network protocol analyzer used to capture and inspect network traffic in real-time. It helps diagnose network issues and analyze protocols.

- **Use Case**: Identifying malicious traffic or troubleshooting network problems.

---

## **PCAP Analysis**
PCAP (Packet Capture) analysis involves examining network traffic captured in `.pcap` files. Tools like Wireshark or tcpdump are used to analyze these files.

- **Use Case**: Detecting anomalies, malware, or unauthorized access.

---

## **DNS (Domain Name System)**
DNS translates human-readable domain names (e.g., `google.com`) into IP addresses (e.g., `142.250.190.14`).

- **Use Case**: Resolving domain names for web browsing.

---

## **HTTP (Hypertext Transfer Protocol)**
HTTP is the protocol used for transferring web pages on the internet. It operates over TCP/IP.

- **HTTPS**: A secure version of HTTP that uses encryption (TLS/SSL).

---

## **ARP (Address Resolution Protocol)**
ARP maps IP addresses to MAC addresses on a local network. It helps devices find each other at the data link layer.

- **Use Case**: Resolving IP addresses to MAC addresses for communication.

---

## **SYN Scan**
A SYN scan is a type of port scan used to identify open ports on a target system. It sends SYN packets and analyzes the responses.

- **Use Case**: Network reconnaissance during penetration testing.

---

## **TCP (Transmission Control Protocol)**
TCP is a connection-oriented protocol that ensures reliable, ordered, and error-checked delivery of data between devices.

- **Features**: Three-way handshake, flow control, and error recovery.

---

## **nslookup**
nslookup is a command-line tool used to query DNS servers and retrieve domain name or IP address information.

- **Command**: `nslookup <domain_name>`.

---

## **Network Vulnerability Assessments**
A network vulnerability assessment is the process of identifying, quantifying, and prioritizing vulnerabilities in a network.

- **Tools**: Nessus, OpenVAS, Qualys.
- **Use Case**: Proactively securing a network.

---

## **Network Vulnerability Mitigation**
Mitigation involves taking steps to reduce the risk of vulnerabilities being exploited.

- **Steps**:
  - Apply patches and updates.
  - Configure firewalls and intrusion detection systems (IDS).
  - Implement strong access controls.
  - Conduct regular security audits.

---

This document is a work in progress. Feel free to contribute or expand on these concepts!
```