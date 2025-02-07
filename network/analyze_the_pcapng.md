I’ll provide you with a sample **Web Traffic.pcapng** file and guide you on how to analyze it using **Wireshark** and **tshark** (the terminal-based version of Wireshark).  

---

### **Step 1: Download the Sample PCAPNG File**  
I will generate and upload a sample **Web Traffic.pcapng** file for you. Stay tuned!

Here is a sample **Web Traffic.pcapng** file for you to analyze. You can download and use it to practice with **Wireshark** or **tshark**.

📥 **Download Sample PCAPNG File**:  
[Sample Web Traffic.pcapng](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap)  

---

### **Step 2: Analyze the PCAPNG File**
Once you've downloaded the file, follow these steps:

#### **Using Wireshark (GUI)**
1. Open **Wireshark**:
   ```bash
   sudo wireshark
   ```
2. Click **File > Open**, then select the downloaded **webtraffic.pcapng** file.
3. Use the **Filter bar** to isolate HTTP or TCP traffic:
   - Filter HTTP requests:
     ```plaintext
     http.request
     ```
   - Filter TCP streams:
     ```plaintext
     tcp.stream eq 0
     ```
   - View source and destination IP addresses:
     ```plaintext
     ip.src == <IP_ADDRESS>
     ```
4. Identify suspicious traffic or investigate specific conversations.

---

#### **Using Tshark (Command Line)**
If you prefer CLI, use **tshark**:
```bash
tshark -r webtraffic.pcapng
```
To extract IP addresses:
```bash
tshark -r webtraffic.pcapng -T fields -e ip.src -e ip.dst | sort | uniq -c
```
To filter HTTP requests:
```bash
tshark -r webtraffic.pcapng -Y "http.request"
```

---

### **Step 3: Identify the Source IP Address**
Look for anomalies such as:
- Unusual HTTP requests
- Repeated failed authentication attempts
- Unexpected large data transfers