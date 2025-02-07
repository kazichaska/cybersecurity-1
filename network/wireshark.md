### **1. Capture Live Web Traffic**
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

### **2. Configure Wireshark for Better Visibility**
#### **A. Configure Time to Show Date and Time of Day**
1. Click **View** → **Time Display Format**.
2. Select **Date and Time of Day**.

#### **B. Configure HTTP Traffic to Display in a Distinct Color**
1. Click **View** → **Coloring Rules**.
2. Click **+ (Add a new rule)**.
3. Set **Name**: `HTTP Traffic`.
4. Set **Filter**: `http or tls`.
5. Choose a color (e.g., light blue for better visibility).
6. Click **OK**, then **Apply**.

#### **C. Configure Network Translation to Display Webpages Being Accessed**
1. In the **Display Filter**, enter:
   ```
   http.request
   ```
   - This filter isolates HTTP requests, showing GET and POST requests made to web servers.
   - Look at the **"Host"** and **"Request URI"** fields in the Packet Details pane to see which websites are being accessed.

2. If HTTPS is being used, filter with:
   ```
   tls.handshake.type == 1
   ```
   - This captures TLS Client Hello packets, where the **Server Name Indication (SNI)** field reveals the website being accessed.

#### **D. Add Source & Destination Port Columns**
1. **Right-click** any column header → Click **Column Preferences**.
2. Click **+ (Add Column)**.
3. Set **Title** as `Source Port`, Type as `Src Port`.
4. Click **+ (Add Column)** again and add `Destination Port` as `Dst Port`.

#### **E. Remove "New Column"**
1. Right-click on **New Column** → Click **Remove**.

---

### **3. Confirm Your Settings**
1. Visit any website in your browser while capturing.
2. Apply the filters (`http.request` or `tls.handshake.type == 1`).
3. Verify that Wireshark displays:
   - Date & Time
   - HTTP requests in a distinct color
   - Webpage URLs in the **Host** or **SNI** fields
   - Source and Destination Ports


### And more with `wireshark` ###

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




#### And more here ####

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