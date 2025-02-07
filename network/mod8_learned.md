```markdown
# Network Fundamentals

## Identify Clients, Servers, Requests, and Responses in Network Communications

- **Clients**: Devices or software that request services or resources from servers.
- **Servers**: Devices or software that provide services or resources to clients.
- **Requests**: Messages sent from clients to servers to request services or resources.
- **Responses**: Messages sent from servers to clients in reply to their requests.

## Identify How AI/ML Can Benefit Networking

- **Traffic Analysis**: AI/ML can analyze network traffic patterns to detect anomalies and potential security threats.
- **Predictive Maintenance**: AI/ML can predict hardware failures and network issues before they occur, allowing for proactive maintenance.
- **Optimization**: AI/ML can optimize network performance by dynamically adjusting configurations based on real-time data.

## Design a Conceptual Network Made of Various Network and Network Security Devices

- **Router**: Connects different networks and directs data packets between them.
- **Switch**: Connects devices within the same network and forwards data based on MAC addresses.
- **Firewall**: Monitors and controls incoming and outgoing network traffic based on security rules.
- **IDS/IPS**: Intrusion Detection/Prevention Systems that monitor network traffic for suspicious activity and take action to prevent breaches.
- **VPN Gateway**: Provides secure remote access to the network.

## Convert Binary Numeric Representations to Readable IP Addresses and Determine to Which Servers the IP Addresses Belong

- **Binary to IP Conversion**: Convert binary numbers to decimal format to get the readable IP address.
  - Example: `11000000.10101000.00000001.00000001` converts to `192.168.1.1`
- **IP Address Lookup**: Use tools like `nslookup` or online services to determine the server associated with an IP address.

## Modify Hosts Files to Circumvent DNS and Redirect the Access of a Website

- **Hosts File Location**:
  - Windows: `C:\Windows\System32\drivers\etc\hosts`
  - Linux/Mac: `/etc/hosts`
- **Modification Example**:
  - Add an entry to redirect `example.com` to `192.168.1.1`:
    ```
    192.168.1.1 example.com
    ```
  - Save the file and flush DNS cache if necessary.

```

You can save this content in the 

network-fundamentals.md

 file.

kazichaska: same for the following for ports-protocol-osi_model.md document

Interpret data in network packets by analyzing their headers, payloads, and trailers.

Explain the role of ports in specifying a network packet's destination.

Associate common protocols with their assigned ports.

Explain how encapsulation and decapsulation allow different protocols to interact with each other.

Use the layers of the OSI model to identify sources of problems on a network.

Capture and analyze live network traffic using Wireshark.

GitHub Copilot: Here is the updated content for 

ports-protocol-osi_model.md

:

```markdown
# Ports, Protocols, and OSI Model

## Interpret Data in Network Packets by Analyzing Their Headers, Payloads, and Trailers

- **Headers**: Contain metadata about the packet, such as source and destination addresses, protocol information, and packet sequencing.
- **Payloads**: The actual data being transmitted.
- **Trailers**: Include error-checking information to ensure data integrity.

## Explain the Role of Ports in Specifying a Network Packet's Destination

- **Ports**: Numerical identifiers in the transport layer that specify the destination application or service on a host.
  - Example: HTTP uses port 80, HTTPS uses port 443.

## Associate Common Protocols with Their Assigned Ports

- **HTTP**: Port 80
- **HTTPS**: Port 443
- **FTP**: Ports 20 and 21
- **SSH**: Port 22
- **DNS**: Port 53
- **SMTP**: Port 25
- **IMAP**: Port 143
- **POP3**: Port 110

## Explain How Encapsulation and Decapsulation Allow Different Protocols to Interact with Each Other

- **Encapsulation**: Wrapping data with protocol-specific headers and trailers as it moves down the OSI layers.
- **Decapsulation**: Removing headers and trailers as data moves up the OSI layers.
- **Interaction**: Encapsulation and decapsulation allow data to be transmitted across different network protocols and devices.

## Use the Layers of the OSI Model to Identify Sources of Problems on a Network

- **Physical Layer**: Check cables, connectors, and hardware.
- **Data Link Layer**: Verify MAC addresses and switch configurations.
- **Network Layer**: Ensure correct IP addressing and routing.
- **Transport Layer**: Check port configurations and firewall rules.
- **Session Layer**: Verify session establishment and termination.
- **Presentation Layer**: Ensure data format and encryption.
- **Application Layer**: Check application configurations and services.

## Capture and Analyze Live Network Traffic Using Wireshark

- **Wireshark**: A tool for capturing and analyzing network traffic.
  - **Capture**: Start a capture session to collect live network packets.
  - **Analyze**: Use filters and inspection tools to analyze packet headers, payloads, and trailers.
  - **Example**: Filter by protocol (e.g., `http`, `tcp`) to focus on specific traffic types.

```

You can save this content in the 

ports-protocol-osi_model.md

 file.

kazichaska: create .md file with the following

Wireshark for analyzing web traffic and lot more steps to make it easy for someone to use it as daily basis and also add tips with example to figure out any suspicious traffic


GitHub Copilot: Here is the updated content for 

wireshark.md

:

```markdown
# Wireshark Guide for Analyzing Web Traffic

## 1. Capture Live Web Traffic

1. **Start Wireshark**: Open Wireshark with administrative privileges.
   - On Linux:  
     ```bash
     sudo wireshark
     ```
   - On Windows: Run as Administrator.

2. **Select the Network Interface**:  
   - Choose the correct network adapter (e.g., `eth0`, `Wi-Fi`, `Ethernet`).
   - Click **Start** to begin capturing traffic.

## 2. Configure Wireshark for Better Visibility

### A. Configure Time to Show Date and Time of Day

1. Click **View** → **Time Display Format**.
2. Select **Date and Time of Day**.

### B. Configure HTTP Traffic to Display in a Distinct Color

1. Click **View** → **Coloring Rules**.
2. Click **+ (Add a new rule)**.
3. Set **Name**: `HTTP Traffic`.
4. Set **Filter**: `http or tls`.
5. Choose a color (e.g., light blue for better visibility).
6. Click **OK**, then **Apply**.

### C. Configure Network Translation to Display Webpages Being Accessed

1. In the **Display Filter**, enter:
   ```wireshark
   http.host
   ```
2. This will show the hostnames of the websites being accessed.

## 3. Tips for Analyzing Suspicious Traffic

### A. Identify Unusual Traffic Patterns

1. Look for large amounts of data being sent to unknown IP addresses.
2. Check for repeated connection attempts to the same IP address.

### B. Use Filters to Isolate Suspicious Traffic

1. **Filter by IP Address**:
   ```wireshark
   ip.addr == 192.168.1.1
   ```
2. **Filter by Protocol**:
   ```wireshark
   http or tls
   ```
3. **Filter by Port**:
   ```wireshark
   tcp.port == 80 or tcp.port == 443
   ```

### C. Inspect Packet Details

1. Right-click on a packet and select **Follow** → **TCP Stream** to see the full conversation.
2. Check the packet details for unusual payloads or headers.

### D. Use Wireshark's Built-in Tools

1. **Statistics** → **Protocol Hierarchy**: View the distribution of protocols in the captured traffic.
2. **Statistics** → **Conversations**: Identify the top talkers in the network.

## 4. Save and Export Captures

1. **Save Capture**: Click **File** → **Save As** to save the capture file for later analysis.
2. **Export Specific Packets**: Click **File** → **Export Specified Packets** to export a subset of the captured traffic.

## 5. Additional Resources

- **Wireshark User Guide**: [Wireshark Documentation](https://www.wireshark.org/docs/)
- **Wireshark Tutorials**: [Wireshark University](https://www.wireshark.org/docs/wsug_html_chunked/)

```

You can save this content in the `wireshark.md` file.
You can save this content in the `wireshark.md` file.

kazichaska: write an .md file with the following content which would help me now and in future 

Protocols are standardized rules that dictate how data is communicated.
Ports assist with where the data is transmitted to and from, with respect to the server and client.
The seven layers of the OSI model conceptualize how data is communicated across a network.
Wireshark is a powerful utility for in-depth analysis of network packets.
In this lesson, we will cover the following concepts:
The process of gathering data for a specific network, known as enumeration.
The Layer 2 Data Link protocol ARP, used to transfer network traffic within a local network.
The Layer 3 Network utilities ping and traceroute, used by network and security professionals to diagnose network issues.
The Layer 4 Transport protocols TCP and UDP and how TCP establishes a connection with a three-way handshake.
SYN scans and how both security professionals and attackers can use this method to determine the state of ports in a network.


GitHub Copilot: Here is the updated content for 

data_flow_through_layers2_3_4.md

:

```markdown
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

### Layer 2: Data Link Protocol ARP

- **ARP (Address Resolution Protocol)**: Used to transfer network traffic within a local network.
- **Function**: Maps IP addresses to MAC addresses, allowing devices to communicate within the same network.

### Layer 3: Network Utilities

- **Ping**: Used to test the reachability of a host on an IP network and measure the round-trip time for messages.
- **Traceroute**: Used to trace the path that packets take from source to destination, helping diagnose network issues.

### Layer 4: Transport Protocols

- **TCP (Transmission Control Protocol)**: Establishes a connection with a three-way handshake (SYN, SYN-ACK, ACK).
- **UDP (User Datagram Protocol)**: A connectionless protocol that sends data without establishing a connection.

### SYN Scans

- **Definition**: A method used to determine the state of ports in a network.
- **Usage**: Both security professionals and attackers use SYN scans to identify open, closed, or filtered ports.

## Conclusion

Understanding these concepts is crucial for network and security professionals to effectively manage and secure network communications. Tools like Wireshark can provide valuable insights into network traffic and help diagnose issues at various layers of the OSI model.

```

You can save this content in the 

data_flow_through_layers2_3_4.md

 file.

kazichaska: need some hands of examples with this

GitHub Copilot: Here is the updated content for 

data_flow_through_layers2_3_4.md

 with hands-on examples:

```markdown
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

```

You can save this content in the `data_flow_through_layers2_3_4.md` file.
You can save this content in the `data_flow_through_layers2_3_4.md` file.

kazichaska: provide most used or useful wireshark flags like this one tcp.flags.syn == 0 && tcp.flags.ack == 1 on the .md document for future reference

GitHub Copilot: Here is the updated content for 

wireshark.md

 with useful Wireshark flags:

```markdown
# Wireshark Guide for Analyzing Web Traffic

## 1. Capture Live Web Traffic

1. **Start Wireshark**: Open Wireshark with administrative privileges.
   - On Linux:  
     ```bash
     sudo wireshark
     ```
   - On Windows: Run as Administrator.

2. **Select the Network Interface**:  
   - Choose the correct network adapter (e.g., `eth0`, `Wi-Fi`, `Ethernet`).
   - Click **Start** to begin capturing traffic.

---

## 2. Configure Wireshark for Better Visibility

### A. Configure Time to Show Date and Time of Day

1. Click **View** → **Time Display Format**.
2. Select **Date and Time of Day**.

### B. Configure HTTP Traffic to Display in a Distinct Color

1. Click **View** → **Coloring Rules**.
2. Click **+ (Add a new rule)**.
3. Set **Name**: `HTTP Traffic`.
4. Set **Filter**: `http or tls`.
5. Choose a color (e.g., light blue for better visibility).
6. Click **OK**, then **Apply**.

### C. Configure Network Translation to Display Webpages Being Accessed

1. In the **Display Filter**, enter:
   ```wireshark
   http.host
   ```
2. This will show the hostnames of the websites being accessed.

---

## 3. Useful Wireshark Flags

### TCP Flags

- **SYN and ACK**: Filter for TCP packets with SYN and ACK flags.
  ```wireshark
  tcp.flags.syn == 1 && tcp.flags.ack == 1
  ```
- **Only ACK**: Filter for TCP packets with only the ACK flag.
  ```wireshark
  tcp.flags.ack == 1 && tcp.flags.syn == 0
  ```
- **Only SYN**: Filter for TCP packets with only the SYN flag.
  ```wireshark
  tcp.flags.syn == 1 && tcp.flags.ack == 0
  ```
- **RST**: Filter for TCP packets with the RST flag.
  ```wireshark
  tcp.flags.reset == 1
  ```
- **FIN**: Filter for TCP packets with the FIN flag.
  ```wireshark
  tcp.flags.fin == 1
  ```

### HTTP and HTTPS

- **HTTP Requests**: Filter for HTTP GET requests.
  ```wireshark
  http.request.method == "GET"
  ```
- **HTTPS Traffic**: Filter for HTTPS traffic.
  ```wireshark
  tls
  ```

### DNS

- **DNS Queries**: Filter for DNS query packets.
  ```wireshark
  dns.flags.response == 0
  ```
- **DNS Responses**: Filter for DNS response packets.
  ```wireshark
  dns.flags.response == 1
  ```

### ICMP

- **ICMP Echo Requests**: Filter for ICMP echo request packets (ping).
  ```wireshark
  icmp.type == 8
  ```
- **ICMP Echo Replies**: Filter for ICMP echo reply packets (ping response).
  ```wireshark
  icmp.type == 0
  ```

---

## 4. Tips for Analyzing Suspicious Traffic

### A. Identify Unusual Traffic Patterns

1. Look for large amounts of data being sent to unknown IP addresses.
2. Check for repeated connection attempts to the same IP address.

### B. Use Filters to Isolate Suspicious Traffic

1. **Filter by IP Address**:
   ```wireshark
   ip.addr == 192.168.1.1
   ```
2. **Filter by Protocol**:
   ```wireshark
   http or tls
   ```
3. **Filter by Port**:
   ```wireshark
   tcp.port == 80 or tcp.port == 443
   ```

### C. Inspect Packet Details

1. Right-click on a packet and select **Follow** → **TCP Stream** to see the full conversation.
2. Check the packet details for unusual payloads or headers.

### D. Use Wireshark's Built-in Tools

1. **Statistics** → **Protocol Hierarchy**: View the distribution of protocols in the captured traffic.
2. **Statistics** → **Conversations**: Identify the top talkers in the network.

---

## 5. Save and Export Captures

1. **Save Capture**: Click **File** → **Save As** to save the capture file for later analysis.
2. **Export Specific Packets**: Click **File** → **Export Specified Packets** to export a subset of the captured traffic.

---

## 6. Additional Resources

- **Wireshark User Guide**: [Wireshark Documentation](https://www.wireshark.org/docs/)
- **Wireshark Tutorials**: [Wireshark University](https://www.wireshark.org/docs/wsug_html_chunked/)

```

You can save this content in the `wireshark.md` file.
You can save this content in the `wireshark.md` file.

kazichaska: provide documentation as .md file with the following items with some examples for future references

Identify clients, servers, requests, and responses in network communications.
Identify network topologies and compare their advantages and disadvantages.
Design a conceptual network made of various network and network security devices.
Convert binary numeric representations to readable IP addresses and determine which servers the IP addresses belong to.
Modify hosts files to circumvent DNS and redirect the access of a website.
Interpret data in network packets by analyzing their headers, payloads, and trailers.
Explain the role of ports in specifying a network packet's destination.
Associate common protocols with their assigned ports.
Explain how encapsulation and decapsulation allow different protocols to interact with each other.
Use the layers of the OSI model to identify sources of problems on a network.
Capture and analyze live network traffic using Wireshark.
Define enumeration as a set of methods used by security professionals and hackers to determine network vulnerabilities.
Use Wireshark to visualize and analyze ARP activity, including ARP spoofing.
Use ping and fping to determine if hosts are up and accepting connections.
Use traceroute to troubleshoot networking communication issues between two devices.
Define and distinguish TCP and UDP.
Analyze TCP traffic in Wireshark.
Analyze SYN scans to determine the availability of ports on a network.

GitHub Copilot: Here is the updated content for 

mod8_learned.md

:

```markdown
# Module 8: Key Concepts and Examples

## Identify Clients, Servers, Requests, and Responses in Network Communications

- **Clients**: Devices or software that request services or resources from servers.
- **Servers**: Devices or software that provide services or resources to clients.
- **Requests**: Messages sent from clients to servers to request services or resources.
- **Responses**: Messages sent from servers to clients in reply to their requests.
- **Example**: A web browser (client) sends an HTTP GET request to a web server, which responds with the requested web page.

## Identify Network Topologies and Compare Their Advantages and Disadvantages

- **Star Topology**: All devices are connected to a central hub.
  - **Advantages**: Easy to install and manage, failure of one device does not affect others.
  - **Disadvantages**: Central hub failure affects the entire network.
- **Bus Topology**: All devices share a common communication line.
  - **Advantages**: Easy to install, requires less cable.
  - **Disadvantages**: Difficult to troubleshoot, a failure in the main cable affects the entire network.
- **Ring Topology**: Devices are connected in a circular fashion.
  - **Advantages**: Data is transferred quickly, easy to identify faults.
  - **Disadvantages**: Failure of one device can affect the entire network.

## Design a Conceptual Network Made of Various Network and Network Security Devices

- **Router**: Connects different networks and directs data packets between them.
- **Switch**: Connects devices within the same network and forwards data based on MAC addresses.
- **Firewall**: Monitors and controls incoming and outgoing network traffic based on security rules.
- **IDS/IPS**: Intrusion Detection/Prevention Systems that monitor network traffic for suspicious activity and take action to prevent breaches.
- **VPN Gateway**: Provides secure remote access to the network.

## Convert Binary Numeric Representations to Readable IP Addresses and Determine Which Servers the IP Addresses Belong To

- **Binary to IP Conversion**: Convert binary numbers to decimal format to get the readable IP address.
  - **Example**: `11000000.10101000.00000001.00000001` converts to `192.168.1.1`
- **IP Address Lookup**: Use tools like `nslookup` or online services to determine the server associated with an IP address.

## Modify Hosts Files to Circumvent DNS and Redirect the Access of a Website

- **Hosts File Location**:
  - Windows: `C:\Windows\System32\drivers\etc\hosts`
  - Linux/Mac: `/etc/hosts`
- **Modification Example**:
  - Add an entry to redirect `example.com` to `192.168.1.1`:
    ```
    192.168.1.1 example.com
    ```
  - Save the file and flush DNS cache if necessary.

## Interpret Data in Network Packets by Analyzing Their Headers, Payloads, and Trailers

- **Headers**: Contain metadata about the packet, such as source and destination addresses, protocol information, and packet sequencing.
- **Payloads**: The actual data being transmitted.
- **Trailers**: Include error-checking information to ensure data integrity.

## Explain the Role of Ports in Specifying a Network Packet's Destination

- **Ports**: Numerical identifiers in the transport layer that specify the destination application or service on a host.
  - Example: HTTP uses port 80, HTTPS uses port 443.

## Associate Common Protocols with Their Assigned Ports

- **HTTP**: Port 80
- **HTTPS**: Port 443
- **FTP**: Ports 20 and 21
- **SSH**: Port 22
- **DNS**: Port 53
- **SMTP**: Port 25
- **IMAP**: Port 143
- **POP3**: Port 110

## Explain How Encapsulation and Decapsulation Allow Different Protocols to Interact with Each Other

- **Encapsulation**: Wrapping data with protocol-specific headers and trailers as it moves down the OSI layers.
- **Decapsulation**: Removing headers and trailers as data moves up the OSI layers.
- **Interaction**: Encapsulation and decapsulation allow data to be transmitted across different network protocols and devices.

## Use the Layers of the OSI Model to Identify Sources of Problems on a Network

- **Physical Layer**: Check cables, connectors, and hardware.
- **Data Link Layer**: Verify MAC addresses and switch configurations.
- **Network Layer**: Ensure correct IP addressing and routing.
- **Transport Layer**: Check port configurations and firewall rules.
- **Session Layer**: Verify session establishment and termination.
- **Presentation Layer**: Ensure data format and encryption.
- **Application Layer**: Check application configurations and services.

## Capture and Analyze Live Network Traffic Using Wireshark

- **Wireshark**: A tool for capturing and analyzing network traffic.
  - **Capture**: Start a capture session to collect live network packets.
  - **Analyze**: Use filters and inspection tools to analyze packet headers, payloads, and trailers.
  - **Example**: Filter by protocol (e.g., `http`, `tcp`) to focus on specific traffic types.

## Define Enumeration as a Set of Methods Used by Security Professionals and Hackers to Determine Network Vulnerabilities

- **Enumeration**: The process of gathering information about network resources, services, and potential vulnerabilities.
- **Example**: Using `nmap` to enumerate network devices.
  ```bash
  nmap -sP 192.168.1.0/24
  ```

## Use Wireshark to Visualize and Analyze ARP Activity, Including ARP Spoofing

- **ARP Activity**: Use Wireshark to capture and analyze ARP packets.
  - **Example**: Filter for ARP packets.
    ```wireshark
    arp
    ```
- **ARP Spoofing**: Detect ARP spoofing by identifying suspicious ARP replies.
  - **Example**: Look for multiple IP addresses mapping to the same MAC address.

## Use Ping and Fping to Determine if Hosts Are Up and Accepting Connections

- **Ping**: Test the reachability of a host on an IP network.
  - **Example**: Pinging a website.
    ```bash
    ping www.google.com
    ```
- **Fping**: A faster alternative to ping for checking multiple hosts.
  - **Example**: Pinging multiple hosts.
    ```bash
    fping -a -g 192.168.1.0/24
    ```

## Use Traceroute to Troubleshoot Networking Communication Issues Between Two Devices

- **Traceroute**: Trace the path that packets take from source to destination.
  - **Example**: Running traceroute to a website.
    ```bash
    traceroute www.google.com
    ```

## Define and Distinguish TCP and UDP

- **TCP (Transmission Control Protocol)**: A connection-oriented protocol that ensures reliable data transmission.
- **UDP (User Datagram Protocol)**: A connectionless protocol that sends data without establishing a connection.

## Analyze TCP Traffic in Wireshark

- **TCP Traffic**: Use Wireshark to capture and analyze TCP packets.
  - **Example**: Filter for TCP packets.
    ```wireshark
    tcp
    ```

## Analyze SYN Scans to Determine the Availability of Ports on a Network

- **SYN Scans**: A method used to determine the state of ports in a network.
- **Example**: Performing a SYN scan with `nmap`.
  ```bash
  nmap -sS 192.168.1.1
  ```

```
