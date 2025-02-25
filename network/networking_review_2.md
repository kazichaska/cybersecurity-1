
### **Part 2: ARP**
**Step 1: Filtering ARP traffic**
1. Apply the filter: `arp`
2. Verify that there are 115 ARP packets.

#### **Answers**
- **What does ARP stand for?**  
  Address Resolution Protocol  
- **What service does ARP provide?**  
  Resolves an IP address to a MAC address.  
- **Which OSI layer does ARP exist in?**  
  **Data Link Layer (Layer 2)**  
- **What type of networking request does ARP first make?**  
  An ARP **Request** to find the MAC address associated with an IP.

#### **ARP Response Analysis**
- **What is the IP of the device that is responding?**  
  Look for the ARP **Reply** packet.  
- **To what IP is the device responding?**  
  Check the **Target IP** field.  
- **Describe the ARP exchange**  
  1. Device A sends an ARP Request: "Who has IP X.X.X.X? Tell A"  
  2. Device B responds: "I have IP X.X.X.X, my MAC is YY:YY:YY:YY:YY:YY"  

---

### **Part 3: DHCP**
**Step 1: Filtering DHCP traffic**
1. Apply the filter: `dhcp`
2. Verify that there are four DHCP packets.

#### **Answers**
- **What does DHCP stand for?**  
  Dynamic Host Configuration Protocol  
- **What service does DHCP provide?**  
  Assigns IP addresses dynamically.  
- **Which OSI layer does DHCP exist in?**  
  **Application Layer (Layer 7)**  
- **What are the four steps of DHCP?**  
  **DORA** (Discover, Offer, Request, Acknowledgment)

#### **DHCP Discover Packet Analysis**
- **What is the original source IP?**  
  Look at the packet’s `Source IP`.  
- **Why does it have that value?**  
  It's `0.0.0.0` because the device does not yet have an assigned IP.  
- **What is the original destination IP?**  
  **255.255.255.255**  
- **What does that value signify?**  
  It's a **broadcast address**, meaning it's sent to all devices.

#### **DHCP ACK Packet Analysis**
- **What is happening in this packet?**  
  The DHCP server **acknowledges** the request and provides an IP.  
- **What is a DHCP lease?**  
  The **time duration** an IP address is assigned to a device.  
- **What is the DHCP lease time in this packet?**  
  Check the **Lease Time** field in the packet details.  

---

### **Part 4: TCP and UDP**
#### **TCP Analysis**
- **What does TCP stand for?**  
  Transmission Control Protocol  
- **Is TCP connection-oriented or connectionless?**  
  **Connection-oriented**  
- **Which OSI layer does TCP exist in?**  
  **Transport Layer (Layer 4)**  
- **What are the steps in a TCP connection?**  
  **Three-way handshake** (SYN, SYN-ACK, ACK)  
- **What are the steps in a TCP termination?**  
  **Four-way termination** (FIN, ACK, FIN, ACK)  
- **For what activity is TCP establishing a connection?**  
  Based on the destination port (e.g., 443 = HTTPS).  

#### **UDP Analysis**
- **What does UDP stand for?**  
  User Datagram Protocol  
- **Is UDP connection-oriented or connectionless?**  
  **Connectionless**  
- **What types of services benefit from UDP?**  
  **VoIP, video streaming, gaming**  

---

## **Activity File: Networking Review Part 2**
### **Part 1: ARP Attacks**
1. Open `network_attack_review.pcap` in Wireshark.
2. Apply the filter: `arp`

#### **Analysis**
- Describe each of the three packets.
- **What type of attack is this?**  
  Likely an **ARP Spoofing/Poisoning attack**  
- **MAC Address of the Good Device:**  
  Identify the legitimate device's MAC.  
- **MAC Address of the Hacker:**  
  Look for a **duplicate IP address with different MACs**  
- **Potential Impact:**  
  **Man-in-the-Middle (MITM), session hijacking, data theft.**  

---

### **Part 2: DHCP Attacks**
1. Apply the filter: `dhcp`
2. Analyze the DHCP traffic.

#### **Analysis**
- **What type of attack is this?**  
  **DHCP Starvation or Rogue DHCP Server Attack**  
- **Why is the destination IP 255.255.255.255?**  
  DHCP Discover is **broadcasted** to all devices.  
- **Potential Impact:**  
  **Denial of Service (DoS) or MITM attacks.**  

---

### **Part 3: TCP Attacks**
1. Apply the filter: `tcp`

#### **Analysis**
- **What type of attack is this?**  
  Possible **SYN Flood Attack** (TCP connection attempts).  
- **Is this always an attack?**  
  **No**, security professionals use **port scanning** for testing.  
- **Potential Impact:**  
  **Excessive resource consumption, service disruption.**  

---

### **Part 4: Wireless Attacks**
- **Security Types (Least to Most Secure)**  
  **WEP < WPA < WPA2 < WPA3**  
- **What is 802.11?**  
  **Wi-Fi networking standard**  
- **What is an SSID?**  
  **Wireless network name**  
- **What is the WAP signal name?**  
  **Beacon Frame**  
- **Risk of WEP?**  
  **Easily cracked due to weak encryption.**  

---

### **Part 5: Email Attacks**
#### **Email 1 (TurboTax)**
- The email **passes SPF checks**.
- **Legitimate** unless URL analysis says otherwise.

#### **Email 2 (FedEx)**
- SPF **failed**.
- **Spoofed Email - Likely Phishing.**

---

This should give you a full review based on your provided packet captures and email reviews. Let me know if you need further breakdowns! 🚀