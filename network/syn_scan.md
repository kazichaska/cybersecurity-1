A **SYN scan** is a type of **TCP port scan** used to determine which ports on a target system are open, closed, or filtered. It is often called a **half-open scan** because it does not complete the full **three-way handshake** (SYN → SYN-ACK → ACK). Instead, it sends a **SYN** packet and analyzes the response.

---

## **🔹 Step 1: Set Up the Environment**
You need:
- A **Linux** or **Kali Linux** machine (or any system with Nmap installed).
- The **Nmap** tool (default on Kali, install using `sudo apt install nmap`).
- A **target system** (this can be a local network machine or a remote server you have permission to scan).

---

## **🔹 Step 2: Basic SYN Scan with Nmap**
Run the following command:
```bash
sudo nmap -sS <target>
```
Example:
```bash
sudo nmap -sS 192.168.1.10
```
**Why use `sudo`?**  
A SYN scan requires **raw packet manipulation**, which needs root privileges.

---

## **🔹 Step 3: Scanning Specific Ports**
By default, Nmap scans the **1,000 most common ports**. To scan a specific port or range:
```bash
sudo nmap -sS -p 22,80,443 192.168.1.10
```
or scan all **65,535** ports:
```bash
sudo nmap -sS -p- 192.168.1.10
```

---

## **🔹 Step 4: Scanning a Host with Stealth Mode**
To avoid detection by IDS/IPS, you can use:
```bash
sudo nmap -sS -T2 <target>
```
`-T2` slows down the scan to avoid triggering security alarms.

---

## **🔹 Step 5: Save the Scan Results**
To export results to a file:
```bash
sudo nmap -sS -oN synscan_results.txt 192.168.1.10
```

---

## **🔹 Step 6: Capture the SYN Scan in Wireshark**
1. **Open Wireshark** on your machine.
2. Use the capture filter:
   ```
   tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```
3. Run the SYN scan (`nmap -sS <target>`).
4. Observe the packets being sent and responses.

---

## **🔹 Step 7: Interpreting the Results**
- **SYN-ACK response** → The port is **open**.
- **RST-ACK response** → The port is **closed**.
- **No response / ICMP error** → The port is **filtered**.
