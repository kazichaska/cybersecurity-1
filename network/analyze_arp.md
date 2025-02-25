```
192.168.47.1 - Duplicate IP address detected for 192.168.47.1 (00:0c:29:1d:b3:b1) - also in use by 00:50:56:c0:00:08 (frame 22)

192.168.47.2 - Duplicate IP address detected for 192.168.47.2 (00:0c:29:1d:b3:b1) - also in use by 00:50:56:fd:2f:16 (frame 279)

192.168.47.200 - Duplicate IP address detected for 192.168.47.200 (00:0c:29:1d:b3:b1) - also in use by 00:0c:29:0f:71:a3 (frame 224)

192.168.47.254 - Duplicate IP address detected for 192.168.47.254 (00:0c:29:1d:b3:b1) - also in use by 00:50:56:f9:f5:54 (frame 278)


00:0c:29:1d:b3:b1 - Vmware
00:50:56:c0:00:08 - Vmware


```

### **Analysis of the Wireshark Capture (ARP Activity)**

Your Wireshark capture shows **duplicate IP address detection for `192.168.47.1`**, which is an indicator of a potential **ARP spoofing** or misconfiguration issue.

---

### **Findings**
1. **Duplicate IP Detected**  
   - The same IP address (`192.168.47.1`) is being used by two different MAC addresses:  
     - **00:0c:29:1d:b3:b1 (VMware)**  
     - **00:50:56:c0:00:08 (VMware)**  
   - This could be:
     - **Legitimate conflict** due to misconfiguration.
     - **Malicious ARP spoofing attempt** to intercept network traffic.

2. **ARP Replies Indicate a Possible MITM Attack**
   - The `arp.opcode == 2` filter shows **unsolicited ARP replies**.
   - If an attacker is sending forged ARP replies, they can reroute traffic through their machine.

3. **Potential Consequences**
   - **Denial-of-Service (DoS):** Conflicting IPs can cause network instability.
   - **Man-in-the-Middle (MITM) Attack:** If an attacker is spoofing the gateway, they can intercept or alter communications.
   - **Security Breach:** Sensitive credentials and data might be exposed.

---

### **Next Steps for Investigation**
- **Check if `192.168.47.1` is a critical system (e.g., gateway or DHCP server).**
- **Verify ARP tables on affected machines** using:
  ```bash
  arp -a
  ```
- **Identify the MAC vendor** for unknown MAC addresses using a lookup tool:
  - [https://macvendors.com/](https://macvendors.com/)
- **Monitor ARP traffic in real-time** using:
  ```bash
  watch -n 1 arp -a
  ```

---

### **Recommendations for Mitigation**
1. **Use Static ARP Entries**
   - Configure static ARP mappings for critical systems (e.g., gateway, DNS server).
   ```bash
   arp -s 192.168.47.1 00:0c:29:1d:b3:b1
   ```

2. **Enable Dynamic ARP Inspection (DAI)**
   - If using **managed switches**, enable DAI to prevent ARP spoofing.

3. **Segment the Network**
   - Use VLANs to separate trusted and untrusted devices.

4. **Implement ARP Spoofing Detection Tools**
   - Use tools like **Arpwatch** or **XArp** to detect suspicious ARP activity.

---


### **How to Analyze ARP Activity for Security Vulnerabilities in Wireshark**
Now that you have filtered the ARP packets and identified the MAC addresses associated with the IPs, let's analyze them for **potential security vulnerabilities**.

---

## **1. Look for ARP Spoofing / Poisoning**
### **Steps:**
1. **Check for Duplicate IP Addresses:**
   - **Wireshark Filter:**
     ```
     arp.duplicate-address-frame
     ```
   - If multiple MAC addresses are claiming the **same IP**, it indicates potential **ARP spoofing**.

2. **Check for Unexpected MAC Changes:**
   - In the ARP table (`arp.src.hw_mac` field), verify if any **MAC address suddenly changes** for a known IP.
   - If an IP (e.g., `192.168.47.1`) is associated with multiple MAC addresses, an attacker might be intercepting traffic.

3. **Identify Gratuitous ARP Packets:**
   - **Filter:**
     ```
     arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.47.1
     ```
   - If an IP frequently sends ARP **Reply (Opcode 2) packets** without a preceding request, it might be trying to poison the ARP cache.

---

## **2. Check for Unauthorized Devices**
### **Steps:**
1. **Identify MAC Vendors:**
   - **Right-click a MAC address** → **Copy** → Use an online MAC lookup tool like [https://macvendors.com/](https://macvendors.com/)
   - If you see **unknown vendors** or **non-CompuCom devices**, investigate them.
   - Example: If a critical gateway (`192.168.47.254`) has a **non-standard vendor**, it might be an imposter device.

2. **Look for Unusual ARP Requests:**
   - If a device is constantly broadcasting `Who has` requests, it might be scanning the network.
   - **Filter for frequent requests:**
     ```
     arp.opcode == 1
     ```
   - If a **single device** sends too many ARP requests in a short period, it might be mapping the network for attacks.

---

## **3. Validate Gateway Integrity**
### **Steps:**
1. **Check if the Default Gateway (`192.168.47.254`) is Consistently Used**
   - If an unknown MAC address claims to be the **gateway**, there is likely an attack.
   - **Filter for gateway ARP responses:**
     ```
     arp.dst.proto_ipv4 == 192.168.47.254
     ```
   - If multiple MAC addresses respond, an ARP poisoning attack may be happening.

---

## **4. Check for Rogue DHCP Servers**
### **Steps:**
1. If `192.168.47.200` is an expected DHCP server, check if **another device** is also giving out leases.
2. **Filter DHCP Traffic (if present):**
   ```
   bootp
   ```
   - If two devices claim to be the **DHCP server**, an attacker could be performing **MITM (Man-in-the-Middle) attacks**.

---

## **5. Check for Non-Local MAC Addresses**
### **Steps:**
1. Verify if any MAC address does not belong to the local network range.
2. Use:
   ```
   eth.addr_resolved
   ```
   - If an external or public MAC appears, a **rogue device** may be present.

---

## **Summary for CompuCorp**
Based on your analysis, you should summarize:
- **Any duplicate IP-MAC mappings (possible ARP spoofing)**
- **Unknown vendors (possible rogue devices)**
- **Gateway inconsistencies (possible MITM attacks)**
- **Excessive ARP requests (network reconnaissance activity)**

---

## **Bonus: How to Prevent ARP-Related Attacks**
1. **Use Static ARP Entries** (Locks IP-to-MAC mappings)
2. **Enable Dynamic ARP Inspection (DAI)** on managed switches
3. **Use VLAN Segmentation** to isolate sensitive devices
4. **Monitor ARP Tables** for unusual changes (`arp -a` on Windows/Linux)
5. **Implement Network Access Control (NAC)** to block unknown devices

---

## **Next Steps**
Would you like help drafting a formal **security report** for CompuCorp? 🚀