### **Step 1: Open the Packet Capture File in Wireshark**
- If you haven't already, open the `.pcapng` file in Wireshark.

---

### **Step 2: Filter for TCP Traffic**
- In Wireshark’s **Display Filter** bar, enter the following filter and press **Enter**:
  ```
  tcp
  ```
  - This will filter out all non-TCP traffic and show only TCP packets.

- To specifically find a particular IP’s TCP traffic, you can filter by:
  ```
  ip.addr == <target_IP>
  ```
  Example:
  ```
  ip.addr == 192.168.1.10
  ```

---

### **Step 3: Find TCP Handshakes (Connection Establishment)**
A TCP connection is established using the **three-way handshake**:
1. **SYN** (Client → Server)
2. **SYN-ACK** (Server → Client)
3. **ACK** (Client → Server)

- Use this filter to find all SYN packets (initiating a TCP handshake):
  ```
  tcp.flags.syn == 1 && tcp.flags.ack == 0
  ```
  - Look at the **Source** and **Destination** IPs to determine which machines are initiating connections.

- If you want to view an entire TCP conversation (to see how the handshake completes):
  - Right-click on a **SYN packet** → Select **Follow** → Click **TCP Stream**.
  - This will show the full exchange between the client and server.

---

### **Step 4: Find TCP Terminations (Connection Closing)**
A TCP connection is terminated using:
1. **FIN-ACK** (Initiates closure)
2. **FIN-ACK** (Acknowledgment)
3. **RST (Reset)** (Sometimes used for abrupt closure)

- Use this filter to find termination packets:
  ```
  tcp.flags.fin == 1
  ```
  or
  ```
  tcp.flags.reset == 1
  ```
  - This will help you see when the employee finished communicating with different servers.

---

### **Step 5: Determine What the Employee Did**
Now, we analyze what websites and services they accessed.

1. **Find Websites Visited**
   - Look for HTTP or HTTPS traffic:
     ```
     http || tls
     ```
   - Check the **Host** field in HTTP packets to find visited domains.
   - If the domain name is not visible, you can try extracting the IP addresses from the packets.

2. **Look Up IP Addresses**
   - If Wireshark does not resolve IP addresses to domain names:
     - Go to [MXToolbox Reverse Lookup](https://mxtoolbox.com/ReverseLookup.aspx).
     - Enter the IP address to see which domain it belongs to.

3. **Identify Services Used**
   - If you see traffic on **port 80**, it’s likely unencrypted web browsing (HTTP).
   - **Port 443** is encrypted web traffic (HTTPS).
   - **Port 21** is FTP, **Port 22** is SSH, **Port 25** is SMTP (email), etc.
   - You can filter by specific ports using:
     ```
     tcp.port == 443
     ```
     (Replace `443` with the port of interest.)

---

### **Step 6: Summarize Findings**
- Based on the handshake analysis and IP/domain lookups, write a summary of what the employee did.
- Example questions to answer:
  - What websites did they visit?
  - Did they access any internal company resources?
  - Were any suspicious connections made?
  - Any unexpected file transfers?

---

### **Bonus: Analyzing Suspicious Activity**
- If an IP looks suspicious, check it on:
  - [VirusTotal](https://www.virustotal.com/)
  - [Shodan](https://www.shodan.io/)
  - [Whois Lookup](https://who.is/)




----------------------------------------------------------------------------------------


### **Step 1: Open the Packet Capture in Wireshark**
1. Open **Wireshark** and load the `synscan.pcapng` or `synscandemo.pcapng` file.
2. Start by applying a filter for **SYN packets**:
   ```
   tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```
   This will display only the packets where the scanner sent an initial **SYN request**.

---

### **Step 2: Identify Open, Closed, and Filtered Ports**
The responses from the target system will help determine the port state:

- **Open Ports**:  
  - If the target replies with a **SYN-ACK** (`tcp.flags.syn == 1 && tcp.flags.ack == 1`), the port is open.
  - These ports can be confirmed by checking for the final **RST** (reset) sent by the scanner.

- **Closed Ports**:  
  - If the target responds with a **RST-ACK** (`tcp.flags.rst == 1 && tcp.flags.ack == 1`), the port is closed.

- **Filtered Ports**:  
  - If there is **no response**, the port is filtered (likely blocked by a firewall).
  - You can also check for ICMP "Destination Unreachable" messages (`icmp.type == 3`).

---

### **Step 3: Export and Summarize Findings**
1. **List of Open Ports:**  
   - Check the SYN-ACK responses and note the **destination ports**.
   - Example: Ports 22, 80, and 443 responded with SYN-ACK → these are open.

2. **List of Closed Ports:**  
   - Look for RST-ACK responses and note those ports.

3. **Filtered Ports Summary:**  
   - If no response is received for many ports, list them as filtered.

---

### **Step 4: Generate a Short Summary**
Here’s an example of how you can summarize your findings:

**SYN Scan Analysis Summary**
- **Open Ports:** 22 (SSH), 80 (HTTP), 443 (HTTPS)
- **Closed Ports:** 25 (SMTP), 110 (POP3), 445 (SMB)
- **Filtered Ports:** A large number of high-range ports (e.g., 1024-5000) appear to be filtered, likely due to a firewall or network security policy.
