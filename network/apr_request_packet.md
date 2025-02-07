```
Address Resolution Protocol (request)
Hardware type: Ethernet (1)
Protocol type: IPv4 (0x0800)
Hardware size: 6
Protocol size: 4
Opcode: request (1)
Sender MAC address: Technico_65:1a:36 (88:f7:c7:65:1a:36)
Sender IP address: 10.0.0.1
Target MAC address: 00:00:00_00:00:00 (00:00:00:00:00:00)
Target IP address: 10.0.0.6
```


You're looking at an **ARP Request Packet**, which is used to map an **IP address to a MAC address** in a local network.  

### **What’s Happening in This Packet?**
- A device with **MAC address `88:f7:c7:65:1a:36`** (Technico_65:1a:36) and **IP `10.0.0.1`** is **asking who has IP `10.0.0.6`**.
- The **Target MAC is `00:00:00:00:00:00`**, meaning the sender doesn’t know it yet.
- The device with `10.0.0.6` should respond with its MAC address.

### **Why Does This Matter?**
- **Network Discovery:** Normal behavior when a device wants to communicate but doesn’t know the MAC address of `10.0.0.6`.
- **ARP Spoofing Risk:** Attackers can manipulate ARP requests/responses to impersonate devices and intercept traffic.

### **How to Investigate Further?**
1. **Check Who Owns `10.0.0.6`**
   ```bash
   arp -a | grep 10.0.0.6
   ```
2. **Monitor ARP Traffic for Suspicious Activity**
   ```bash
   sudo tcpdump -n -i eth0 arp
   ```
3. **Detect ARP Spoofing (If Multiple MACs Respond to the Same IP)**
   ```bash
   arpwatch -i eth0
   ```