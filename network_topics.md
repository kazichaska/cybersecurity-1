## **🔹 Quick Reference Guide for Networking Concepts**  

---

## **🔹 Subnetting**
### **What is it?**
Subnetting divides a large network into smaller, manageable subnetworks (subnets) to **improve performance, security, and network efficiency**.

### **How to Subnet?**
1. **Determine subnet mask** (e.g., `/24`, `/26`).
2. **Find the number of usable IPs** using:  
   \[
   2^{(32 - \text{subnet mask})} - 2
   \]
3. **Identify network and broadcast addresses**.
4. **Divide the network into subnets**.

### **Example:**
- Given `192.168.1.0/26`
  - Subnet mask: `255.255.255.192`
  - Number of hosts: `2^6 - 2 = 62`
  - Network range: `192.168.1.0 - 192.168.1.63`

---

## **🔹 CIDR (Classless Inter-Domain Routing)**
### **What is CIDR?**
CIDR replaces **class-based networking (A, B, C)** by using **variable-length subnet masks (VLSM)** to allocate IPs efficiently.

### **CIDR Notation Examples:**
| **CIDR** | **Subnet Mask** | **Usable Hosts** |
|----------|---------------|-----------------|
| `/24` | `255.255.255.0` | 254 |
| `/26` | `255.255.255.192` | 62 |
| `/30` | `255.255.255.252` | 2 |

**Calculate Network ID & Broadcast Address**
- `192.168.1.0/28`
  - Subnet Mask: `255.255.255.240`
  - Network ID: `192.168.1.0`
  - Broadcast: `192.168.1.15`

---

## **🔹 IP Addresses**
### **What is an IP Address?**
A unique **numerical identifier** for a device on a network.

### **Types of IPs:**
- **IPv4 (32-bit)** → `192.168.1.1`
- **IPv6 (128-bit)** → `2001:db8::1`

### **Private vs Public IPs**
| **Type** | **Range** |
|----------|----------|
| Private A | `10.0.0.0 - 10.255.255.255` |
| Private B | `172.16.0.0 - 172.31.255.255` |
| Private C | `192.168.0.0 - 192.168.255.255` |

### **IP Addressing Commands**
- Find IP:  
  ```bash
  ip a
  ```
- Check connectivity:
  ```bash
  ping 8.8.8.8
  ```

---

## **🔹 Ping**
### **What is Ping?**
A tool to test **connectivity between two devices**.

### **Syntax**
```bash
ping 192.168.1.1
```
or
```bash
ping google.com
```
- **ICMP Reply** = Host is reachable.
- **Request Timed Out** = No response.

---

## **🔹 OSI Model (7 Layers)**
### **What is the OSI Model?**
A **network framework** that standardizes communication into **7 layers**.

| **Layer** | **Function** | **Example** |
|-----------|-------------|-------------|
| 7 - Application | User Interface | HTTP, FTP, SMTP |
| 6 - Presentation | Encryption, Encoding | SSL, TLS |
| 5 - Session | Connection Management | NetBIOS, RPC |
| 4 - Transport | Reliable Delivery | TCP, UDP |
| 3 - Network | Routing, IP Addressing | IP, ICMP |
| 2 - Data Link | MAC Addressing, Switching | Ethernet, ARP |
| 1 - Physical | Cables, Hardware | Fiber, Copper |

---

## **🔹 Protocols**
### **Common Networking Protocols**
| **Protocol** | **Port** | **Function** |
|-------------|---------|-------------|
| **HTTP** | `80` | Web traffic |
| **HTTPS** | `443` | Secure web traffic |
| **FTP** | `21` | File transfer |
| **SSH** | `22` | Secure remote login |
| **DNS** | `53` | Domain name resolution |
| **DHCP** | `67/68` | IP assignment |

---

## **🔹 Ports**
### **What are Ports?**
Ports identify specific **services running on a system**.

### **Common Port Ranges**
| **Range** | **Type** | **Example** |
|-----------|---------|------------|
| **0-1023** | Well-Known | HTTP (80), SSH (22) |
| **1024-49151** | Registered | MySQL (3306) |
| **49152-65535** | Dynamic | Temporary connections |

### **Check Open Ports**
```bash
sudo netstat -tulnp
```
or
```bash
sudo nmap -p- 192.168.1.1
```

---

## **🔹 Wireshark**
### **What is Wireshark?**
A **packet capture and analysis** tool.

### **Commands**
- Start capture:
  ```bash
  sudo wireshark
  ```
- Filter by IP:
  ```
  ip.addr == 192.168.1.1
  ```
- Filter by Port:
  ```
  tcp.port == 80
  ```

---

## **🔹 PCAP Analysis**
### **What is PCAP?**
A file format used to **capture network packets**.

### **Analyze with Tshark**
```bash
tshark -r capture.pcap
```
- Extract IPs:
  ```bash
  tshark -r capture.pcap -T fields -e ip.src -e ip.dst
  ```
- Extract HTTP traffic:
  ```bash
  tshark -r capture.pcap -Y "http.request"
  ```

---

## **🔹 DNS (Domain Name System)**
### **What is DNS?**
Translates **domain names to IPs**.

### **Check DNS Records**
```bash
nslookup google.com
```
or
```bash
dig google.com
```

---

## **🔹 HTTP (HyperText Transfer Protocol)**
### **What is HTTP?**
A **protocol for web communication**.

### **Common HTTP Status Codes**
| **Code** | **Meaning** |
|----------|------------|
| `200` | OK |
| `301` | Moved Permanently |
| `403` | Forbidden |
| `404` | Not Found |
| `500` | Internal Server Error |

---

## **🔹 ARP (Address Resolution Protocol)**
### **What is ARP?**
Maps **IP addresses to MAC addresses**.

### **Check ARP Table**
```bash
arp -a
```
or
```bash
ip neigh
```

---

## **🔹 SYN Scan**
### **What is a SYN Scan?**
A **stealthy port scan** to detect open/closed ports.

### **Run a SYN Scan**
```bash
sudo nmap -sS -p- 192.168.1.1
```
- **Open port** → SYN/ACK response.
- **Closed port** → RST response.
- **Filtered port** → No response.

---

## **🔹 TCP (Transmission Control Protocol)**
### **What is TCP?**
A **connection-oriented protocol** for reliable data transfer.

### **TCP Handshake**
1. **SYN** → Client sends request.
2. **SYN/ACK** → Server acknowledges.
3. **ACK** → Connection established.

### **Check TCP Connections**
```bash
netstat -an | grep ESTABLISHED
```

---

## **🔹 nslookup**
### **What is nslookup?**
A tool to **query DNS servers**.

### **Example Commands**
- Lookup an IP:
  ```bash
  nslookup google.com
  ```
- Reverse lookup:
  ```bash
  nslookup 8.8.8.8
  ```

---