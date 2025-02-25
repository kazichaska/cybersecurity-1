## **Part 1: HTTP Analysis**
### **Steps to filter HTTP traffic in Wireshark:**
1. Open **Wireshark** and load `reviewpackets.pcapng`.
2. In the **Display Filter**, enter:
   ```
   http
   ```
3. Enable **Name Resolution**:  
   - Go to **Edit > Preferences > Name Resolution** and enable **Resolve Network Addresses**.
4. Identify the **four HTTP packets**.

### **Answers:**
- **HTTP stands for**: Hypertext Transfer Protocol.
- **Port number for HTTP**: **80**.
- **HTTP services**: Facilitates **web browsing**, data retrieval, and web page loading.
- **OSI Layer**: **Layer 7 (Application Layer)**.
- **Website being accessed**: Check the **Host** field in the HTTP request.
- **Source port being used**: Found in the TCP segment of the HTTP request.
- **Port number range**: **Ephemeral ports (49152–65535)**.

#### **Packet 419 Analysis:**
- **Destination MAC Address**: `Technico_65:1a:36 (88:f7:c7:65:1a:36)`.  
- **Represents**: The MAC address of the **destination device** (web server or gateway).
- **OSI Layer**: **Layer 2 (Data Link Layer)**.
- **Devices that use MAC addresses**: **Switches and network interface cards (NICs)**.

---

## **Part 2: ARP Analysis**
### **Steps to filter ARP traffic:**
1. Apply the Wireshark filter:
   ```
   arp
   ```
2. Verify that **115 ARP packets** are displayed.

### **Answers:**
- **ARP stands for**: Address Resolution Protocol.
- **ARP Service**: Resolves **IP addresses to MAC addresses**.
- **OSI Layer**: **Layer 2 (Data Link Layer)**.
- **ARP request type**: **Broadcast request** for a device's MAC address.

#### **ARP Response Analysis:**
- **Filter to count ARP responses**:
   ```
   arp.opcode == 2
   ```
- **Responding device's IP**: (Check `Sender IP Address` in response packets).
- **Requesting IP**: (Check `Target IP Address` in request packets).
- **Explanation**:  
  - **ARP Request**: "Who has **10.0.0.6**? Tell **10.0.0.1**".
  - **ARP Response**: "I (10.0.0.6) am at **MAC 00:1A:2B:3C:4D:5E**".

- **HTTP Traffic:**  
  - Apply filter: `http`
  - Look for four HTTP packets.
  - Identify the website being accessed by checking the `Host` field in the HTTP request.
  
- **ARP Traffic:**  
  - Apply filter: `arp`
  - Count the total ARP packets (should be 115).
  - Find ARP requests (`arp.opcode == 1`) and ARP replies (`arp.opcode == 2`).

- **DHCP Traffic:**  
  - Apply filter: `bootp`
  - Identify the four DHCP packets (Discover, Offer, Request, ACK).

- **TCP and UDP Packets for Specific IP**  
  - Apply filter: `ip.addr == 185.42.236.155`
  - Analyze the five packets, noting TCP three-way handshake (SYN, SYN-ACK, ACK) and UDP packets.

---

## **Part 3: DHCP Analysis**
### **Steps to filter DHCP traffic:**
1. Apply the Wireshark filter:
   ```
   bootp
   ```
2. Identify the **four DHCP packets**.

### **Answers:**
- **DHCP stands for**: Dynamic Host Configuration Protocol.
- **Service provided**: Assigns **IP addresses dynamically**.
- **OSI Layer**: **Layer 7 (Application Layer)**.
- **DHCP Four Steps**:  
  1. **Discover** – Client broadcasts request.  
  2. **Offer** – Server responds with an available IP.  
  3. **Request** – Client selects offered IP.  
  4. **ACK** – Server confirms assignment.

#### **DHCP Discover Packet Analysis:**
- **Source IP**: `0.0.0.0` (since the client has no assigned IP yet).
- **Destination IP**: `255.255.255.255` (broadcast to all DHCP servers).

#### **DHCP ACK Packet Analysis:**
- **What happens?** Server confirms lease assignment.
- **DHCP Lease**: Time period a device holds an IP before renewal.
- **Lease Time**: (Check `Option 51` in the DHCP packet).

---

## **Part 4: TCP & UDP Analysis**
### **Steps to filter TCP/UDP traffic:**
1. Filter for IP:  
   ```
   ip.addr == 185.42.236.155
   ```
2. Identify **five packets**.

### **TCP Answers:**
- **TCP stands for**: Transmission Control Protocol.
- **Connection type**: **Connection-oriented** (ensures reliable transmission).
- **OSI Layer**: **Layer 4 (Transport Layer)**.
- **TCP Three-Way Handshake**:
  1. SYN (Client → Server)
  2. SYN-ACK (Server → Client)
  3. ACK (Client → Server)
- **TCP Termination**:  
  1. FIN
  2. ACK
  3. FIN
  4. ACK
- **Activity/protocol TCP is used for**: Likely **HTTP or HTTPS session**.
- **Website being accessed**: Found in the **Host** field of HTTP packets.

### **UDP Answers:**
- **UDP stands for**: User Datagram Protocol.
- **Connection type**: **Connectionless** (no handshake, less overhead).
- **Services benefiting from UDP**:
  - **Streaming (Netflix, VoIP, gaming)**
  - **DNS queries**
  - **DHCP communications**

---

## **Part 5: Network Devices, Topologies, and Routing**
### **Topologies**
- **Topology A**: (Star, Bus, or Mesh – identify based on the diagram).
- **Advantages/Disadvantages**:
  - **Star**: Easy management but single failure point at the hub.
  - **Bus**: Simple but prone to traffic collisions.
  - **Mesh**: High redundancy but expensive.

### **Network Devices**
- **Devices 1-4**: Likely **Router, Switch, Hub, Firewall**.
- **Dashed line (5)**: Possibly a **VLAN or VPN** connection.
- **Load Balancer**: Distributes traffic between multiple servers.
- **Placement**: Before web servers to balance client requests.

### **Routing**
- **Protocols using distance**: RIP (Routing Information Protocol).
- **Protocols using speed**: OSPF, EIGRP.
- **Shortest path (hops)**: Use Wireshark’s traceroute analysis.
- **Shortest path (time)**: Consider link speeds.

---

## **Part 6: Network Addressing**
- **Binary**: A numerical system using **0s and 1s**.
- **Binary states**: **ON (1) and OFF (0)**.
- **IP addresses use**: Identify devices on a network.
- **Primary IP versions**: **IPv4 & IPv6**.
- **IPv4 octets**: **Four (8-bit each)**.
- **Convert binary to IP**:
  ```
  11000000.10101000.00100000.00101011 → 192.168.32.43
  ```
- **Primary vs. Public IP**:  
  - **Private IP**: Used in local networks, not routable on the internet.  
  - **Public IP**: Assigned by ISPs, accessible over the internet.
- **CIDR**: Classless Inter-Domain Routing (e.g., `/24` means **255.255.255.0** subnet mask).
- **IP range of `192.18.65.0/24`**:
  ```
  192.18.65.0 - 192.18.65.255
  ```

---

## **Final Notes**
You can use **Wireshark filters** to extract each dataset:  
- **HTTP**: `http`
- **ARP**: `arp`
- **DHCP**: `bootp`
- **TCP/UDP**: `tcp` or `udp`

This guide covers all sections in a **concise manner** while helping you analyze **network traffic effectively** for your cybersecurity class! 🚀