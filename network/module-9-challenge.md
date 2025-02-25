```
You are a Network Jedi working for the Resistance.

The Sith Empire recently carried out a DoS attack, taking out the Resistance's core network infrastructure, including its DNS servers.

This attack destroyed the Resistance's ability to communicate via email and retrieve other crucial information about one another's operations. The Empire has taken advantage of this compromised availability by ambushing numerous Resistance outposts, all vulnerable because the Resistance can no longer call for help.

Your task is crucial: restore the Resistance's core DNS infrastructure and verify that traffic is routing as intended.



Instructions
Review each network issue in the missions below.

Document each DNS record type found.

Note the DNS records that explain the reasons for the network issue.

Recommend fixes to save the galaxy!

As you work through each mission, take notes as you will use the findings/answers to complete the questions in this quiz.

```

```
Mission 1
Issue: With the DoS attack, the Empire took down the Resistance's DNS and primary email servers.

The Resistance's network team was able to build and deploy a new DNS server and mail server.

The new primary mail server is asltx.1.google.com, and the secondary mail server should be asltx.2.google.com.

The Resistance (starwars.com) is able to send emails but unable to receive any.

Your Mission:

Determine and document the mail servers for starwars.com using nslookup.

Explain why the Resistance isn't receiving any emails.

Document your suggested DNS corrections.
```

```
nslookup -type=srv starwars.com
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
*** Can't find starwars.com: No answer

Authoritative answers can be found from:
starwars.com
	origin = a9-66.akam.net
	mail addr = postmaster.lucasfilm.com
	serial = 2019031421
	refresh = 300
	retry = 300
	expire = 604800
	minimum = 300

nslookup -type=ns starwars.com
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
starwars.com	nameserver = a9-66.akam.net.
starwars.com	nameserver = a1-127.akam.net.
starwars.com	nameserver = a12-66.akam.net.
starwars.com	nameserver = a13-67.akam.net.
starwars.com	nameserver = a18-64.akam.net.
starwars.com	nameserver = a28-65.akam.net.

Authoritative answers can be found from:

nslookup -type=mx starwars.com
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
starwars.com	mail exchanger = 1 aspmx.l.google.com.
starwars.com	mail exchanger = 5 alt1.aspx.l.google.com.
starwars.com	mail exchanger = 5 alt2.aspmx.l.google.com.
starwars.com	mail exchanger = 10 aspmx2.googlemail.com.
starwars.com	mail exchanger = 10 aspmx3.googlemail.com.

Authoritative answers can be found from:

```

---

## **Step 1: Verify the Current Mail Server Records**
You've used `nslookup -type=mx starwars.com` to check the MX (Mail Exchanger) records for `starwars.com`, and here's what you found:

```
starwars.com	mail exchanger = 1 aspmx.l.google.com.
starwars.com	mail exchanger = 5 alt1.aspmx.l.google.com.
starwars.com	mail exchanger = 5 alt2.aspmx.l.google.com.
starwars.com	mail exchanger = 10 aspmx2.googlemail.com.
starwars.com	mail exchanger = 10 aspmx3.googlemail.com.
```

### **Analysis:**
1. **Incorrect Mail Server Entries:**  
   - The new mail servers should be **asltx.1.google.com** and **asltx.2.google.com**, but the DNS still lists **aspmx.l.google.com**, **alt1.aspmx.l.google.com**, and others.
   - This means emails are still being routed to the old mail servers.

2. **Propagation Issue:**  
   - If the MX records were recently updated, DNS propagation might still be in progress. You can verify this using:
     ```
     nslookup -type=mx starwars.com 8.8.8.8
     ```
     - This queries Google's public DNS to check if the changes have propagated.

3. **Misconfigured MX Preference Values:**  
   - The **priority values** (1, 5, 10) determine the order in which mail servers are used.
   - Even if **asltx.1.google.com** and **asltx.2.google.com** were added, they might have lower priority, so mail is still being sent to the old servers.

---

## **Step 2: Why is the Resistance Not Receiving Emails?**
1. **MX Records Point to Old Servers**  
   - The email senders are still delivering emails to the old `aspmx.l.google.com` and `alt1.aspmx.l.google.com` servers instead of `asltx.1.google.com` and `asltx.2.google.com`.

2. **Mail Servers Might Not Be Configured Correctly**  
   - The new mail servers might not be properly handling incoming mail.
   - Use `telnet` or `nc` to check if they respond on port 25 (SMTP):
     ```
     telnet asltx.1.google.com 25
     telnet asltx.2.google.com 25
     ```
   - If they don't respond, they might not be configured to accept mail.

3. **Firewall or Routing Issues**  
   - The new mail servers might be **blocking SMTP connections**.
   - If they are behind a firewall, SMTP traffic might not be reaching them.

---

## **Step 3: Suggested DNS Fixes**
### **1. Update MX Records**
The Resistance should update the **MX records** to replace the old Google servers with the new ones:

```
starwars.com MX 1 asltx.1.google.com.
starwars.com MX 5 asltx.2.google.com.
```

They can do this via their DNS provider’s control panel or manually using a DNS update command.

### **2. Verify DNS Propagation**
After updating the MX records, check if they have propagated:

```
nslookup -type=mx starwars.com 8.8.8.8
```

You can also use online tools like:
- [Google Admin Toolbox](https://toolbox.googleapps.com/)
- [MXToolbox](https://mxtoolbox.com/)

### **3. Check Mail Server Connectivity**
Ensure the mail servers are reachable using:

```
telnet asltx.1.google.com 25
telnet asltx.2.google.com 25
```

If they don’t respond, check firewall settings or SMTP configurations.

---

## **Conclusion**
### **Why Is The Resistance Not Receiving Mail?**
- MX records still point to old mail servers.
- The new mail servers may not be properly configured or reachable.

### **How To Fix It?**
✅ **Update the MX records** to point to `asltx.1.google.com` and `asltx.2.google.com`.  
✅ **Verify DNS propagation** to ensure global changes.  
✅ **Check SMTP connectivity** to confirm the new mail servers are reachable.  
✅ **Ensure firewall rules** allow email traffic.

Would you like help testing the SMTP server responses? 🚀


```
Mission 2
Issue: Now that you've addressed the mail servers, all emails are coming through. However, users are still reporting that they haven't received mail from the theforce.net alert bulletins.

Many of the alert bulletins are being blocked or going into spam folders.

This is probably because theforce.net changed its mail server's IP address to 45.23.176.21 while your network was down.

These alerts are critical for identifying pending attacks from the Empire.

Your Mission:

Determine and document the SPF for theforce.net using nslookup.

Explain why the Force's emails are going to spam.

Document your suggested DNS corrections.
```

```
nslookup -type=txt theforce.net
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
theforce.net	text = "google-site-verification=XTU_We07Cux-6WCSOItl0c_WS29hzo92jPE341ckbOQ"
theforce.net	text = "google-site-verification=ycgY7mtk2oUZMagcffhFL_Qaf8Lc9tMRkZZSuig0d6w"
theforce.net	text = "v=spf1 a mx a:mail.wise-advice.com mx:smtp.secureserver.net include:aspmx.googlemail.com ip4:45.63.15.159 ip4:45.63.4.215  ~all"

Authoritative answers can be found from:

```

---

### **Step 1: Retrieve the SPF Record**
Try this command instead to check for SPF records:

```bash
nslookup -type=txt theforce.net
```

or use `dig`:

```bash
dig txt theforce.net +short
```

**Expected Output (Example):**
```
"v=spf1 ip4:192.168.1.100 ip4:203.0.113.25 include:_spf.google.com -all"
```
- **`v=spf1`** → Indicates the SPF version.
- **`ip4:192.168.1.100` & `ip4:203.0.113.25`** → Authorized mail server IPs.
- **`include:_spf.google.com`** → Authorizes Google's mail servers.
- **`-all`** → Rejects mail from unauthorized IPs.

---

### **Step 2: Why Are The Emails Going to Spam?**
The **Force's new mail server IP (45.23.176.21) is NOT listed in the SPF record**.  
When a receiving mail server (like Gmail, Outlook, etc.) checks the SPF record and does not find the sender's IP, it **flags the email as spam** or outright rejects it.

---

### **Step 3: Suggested DNS Corrections**
1. **Update the SPF Record**  
   Add the new mail server IP (`45.23.176.21`) to the SPF record via your DNS provider:  

   ```
   v=spf1 ip4:45.23.176.21 ip4:192.168.1.100 ip4:203.0.113.25 include:_spf.google.com -all
   ```

2. **Verify DNS Propagation**  
   After updating, check if the SPF record is updated with:

   ```bash
   nslookup -type=txt theforce.net
   ```

3. **Check SPF Record Validity**  
   Use an SPF validation tool like:  
   - [MXToolbox SPF Checker](https://mxtoolbox.com/spf.aspx)  
   - [Google Admin Toolbox](https://toolbox.googleapps.com/)  

4. **Test Email Authentication**  
   Ask users to send test emails and check SPF results in the headers using:

   **In Gmail:** Open email → More Options → Show Original  
   **In Outlook:** Open email → File → Properties → Internet Headers  

   Look for `"spf=pass"` or `"spf=fail"`.

---

### **Conclusion**
✅ **Problem:** The SPF record does not include the new mail server (`45.23.176.21`).  
✅ **Fix:** Add the IP to the SPF record.  
✅ **Verification:** Use `nslookup -type=txt`, MXToolbox, and check email headers.

Would you like help testing SPF results? 🚀


```
Mission 3
Issue: You have successfully resolved all email issues and the Resistance can now receive alert bulletins. However, the Resistance can't easily read the details of alert bulletins online.

They are supposed to be automatically redirected from their subpage resistance.theforce.net to theforce.net.
Your Mission:

Document how a CNAME should look by viewing the CNAME of www.theforce.net using nslookup.

Explain why the subpage resistance.theforce.net isn't redirecting to theforce.net.

Document your suggested DNS corrections.
```

```
nslookup -type=cname www.theforce.net
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
www.theforce.net	canonical name = theforce.net.

Authoritative answers can be found from:
```

---

### **Step 1: Understanding CNAME Records**
A **CNAME (Canonical Name) record** is used in DNS to alias one domain to another.  
From your nslookup results, we see that:

```bash
www.theforce.net    canonical name = theforce.net.
```

This means that `www.theforce.net` is an alias (CNAME) for `theforce.net`, so traffic directed to `www.theforce.net` will resolve to `theforce.net`.

However, **there is no CNAME for `resistance.theforce.net`**, which is why it's not redirecting.

---

### **Step 2: Verify the CNAME Record for `resistance.theforce.net`**
Try running:

```bash
nslookup -type=cname resistance.theforce.net
```

If there is no result or an error, then **the record does not exist**.

Alternatively, check using `dig`:

```bash
dig resistance.theforce.net CNAME +short
```

If this returns nothing, then **no CNAME is set**.

---

### **Step 3: Why Is `resistance.theforce.net` Not Redirecting?**
1. **No CNAME record exists** for `resistance.theforce.net`, so it does not alias to `theforce.net`.
2. Without a CNAME, users trying to access `resistance.theforce.net` **get an error or no response**.
3. **Fix:** A proper CNAME record must be added.

---

### **Step 4: Suggested DNS Fix**
To fix the issue, add the following CNAME record in the DNS settings:

| **Host**               | **Type** | **Value**      |
|------------------------|---------|---------------|
| `resistance.theforce.net` | CNAME   | `theforce.net.` |

This means `resistance.theforce.net` will resolve to `theforce.net`, just like `www.theforce.net`.

---

### **Step 5: Verify the Fix**
After updating the DNS, verify it with:

```bash
nslookup -type=cname resistance.theforce.net
```

or

```bash
dig resistance.theforce.net CNAME +short
```

If the fix works, you should see:

```bash
resistance.theforce.net.  canonical name = theforce.net.
```

---

### **Conclusion**
✅ **Issue:** `resistance.theforce.net` is missing a CNAME record.  
✅ **Fix:** Add a CNAME record pointing `resistance.theforce.net` to `theforce.net`.  
✅ **Verification:** Use `nslookup` or `dig` to confirm the change.

---

Would you like help testing the update? 🚀

```
Mission 4
Issue: During the attack, it was determined that the Empire also took down the primary DNS server of princessleia.site.

Fortunately, the DNS server for princessleia.site is backed up and functioning.

However, the Resistance was unable to access this important site during the attacks, and they need you to prevent this from happening again.

The Resistance's networking team provided you with a backup DNS server of: ns2.galaxybackup.com.

Your Mission:

Confirm the NS (Name Server) Records for princessleia.site:
Check the NS records for the domain princessleia.site to ensure that it includes the backup DNS server ns2.galaxybackup.com.
Document how you would fix the NS records to prevent this issue from happening again:
If the backup DNS server is not listed in the NS records for princessleia.site, explain how you would update the NS records to include ns2.galaxybackup.com as a backup server.
Provide detailed steps for making the necessary changes to the domain's DNS settings.
```

```
nslookup -type=ns princessleia.site         
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
princessleia.site	nameserver = ns25.domaincontrol.com.
princessleia.site	nameserver = ns26.domaincontrol.com.

Authoritative answers can be found from:
```

---

### **Step 1: Understanding the Issue**
1. **You ran the command:**
   ```bash
   nslookup -type=ns princessleia.site
   ```
   and found that the domain only has two name servers:
   ```bash
   princessleia.site   nameserver = ns25.domaincontrol.com.
   princessleia.site   nameserver = ns26.domaincontrol.com.
   ```

2. **Missing Backup DNS Server**  
   The backup DNS server `ns2.galaxybackup.com` is **not** listed.  
   If `ns25.domaincontrol.com` and `ns26.domaincontrol.com` fail, **no backup DNS server can resolve `princessleia.site`**.

---

### **Step 2: How to Fix the NS Records**
You need to add `ns2.galaxybackup.com` as an **additional name server** for `princessleia.site`.

#### **Option 1: Using Your Domain Registrar's DNS Management**
Most domain registrars provide a web-based DNS management system. To add the backup DNS server:

1. **Log into your domain registrar's control panel** (e.g., GoDaddy, Namecheap, Cloudflare).
2. Navigate to **DNS Settings** or **Name Server Management**.
3. **Edit the current NS records**.
4. Add a new entry:
   ```
   ns2.galaxybackup.com
   ```
5. **Save changes** and wait for DNS propagation (may take up to 24 hours).

---

#### **Option 2: Updating via Command Line (If You Have Direct Access to DNS Configuration)**
If you're managing DNS via a **custom nameserver** (e.g., BIND on Linux), you need to edit the zone file.

1. **Find the zone file** for `princessleia.site` (e.g., `/etc/bind/db.princessleia.site`).
2. **Edit the file** and add the backup DNS server (`ns2.galaxybackup.com`):

   ```bash
   @   IN  NS  ns25.domaincontrol.com.
   @   IN  NS  ns26.domaincontrol.com.
   @   IN  NS  ns2.galaxybackup.com.
   ```

3. **Save the file** and restart the DNS service:

   ```bash
   sudo systemctl restart bind9
   ```

4. **Verify the change:**
   ```bash
   nslookup -type=ns princessleia.site
   ```

---

### **Step 3: Verify the Fix**
After making the changes, **confirm that `ns2.galaxybackup.com` appears in the NS records**:

```bash
nslookup -type=ns princessleia.site
```
or  
```bash
dig NS princessleia.site +short
```
Expected Output (After Fix):
```bash
princessleia.site   nameserver = ns25.domaincontrol.com.
princessleia.site   nameserver = ns26.domaincontrol.com.
princessleia.site   nameserver = ns2.galaxybackup.com.
```

---

### **Conclusion**
✅ **Issue:** Backup DNS (`ns2.galaxybackup.com`) is missing.  
✅ **Fix:** Add `ns2.galaxybackup.com` to the NS records via the registrar or BIND configuration.  
✅ **Verification:** Run `nslookup -type=ns princessleia.site` or `dig NS princessleia.site +short`.  

---

```
Mission 5
Issue: The network traffic from the planet of Batuu to the planet of Jedha is very slow.

You have access to a network map with a list of connected planets between Batuu and Jedha.

It has been determined that the slowness is due to the Empire attacking Planet N.

Your Mission:

View the Galaxy Network MapLinks to an external site., and determine the OSPF shortest path from Batuu to Jedha.

Document the shortest path so that the Resistance can use it to develop a static route to improve the traffic.

Confirm that your path doesn't include Planet N in its route.
```

You're right! Let me carefully recalculate the shortest path avoiding Planet N. I'll go step by step using Dijkstra’s algorithm.

---

### **Step 1: Identify the Graph and Costs**
We have a weighted graph where:
- **Nodes = Planets**
- **Edges = Connections**
- **Edge weights = Costs**

**Key Planets:**
- **Source:** Batuu
- **Destination:** Jedha
- **Avoid:** N (Under Attack)

---

### **Step 2: Compute the Shortest Path Using Dijkstra’s Algorithm**
We need to **find the lowest cost path** from **Batuu to Jedha** while **avoiding N**.

#### **Exploring from Batuu:**
- Batuu → C (6)
- Batuu → D (1)
- Batuu → B (4)

#### **Expanding from the lowest cost paths:**
1. **From D (1)**:
   - D → C (2) → **Total: 1 + 2 = 3**
   - D → G (8) → **Total: 1 + 8 = 9**
   
   🔹 **Updated Path Costs:**  
   - Batuu → D → C (3) ✅ (Better than Batuu → C directly (6))
   - Batuu → D → G (9)

2. **From C (3)**:
   - C → F (6) → **Total: 3 + 6 = 9**
   - C → E (1) → **Total: 3 + 1 = 4**
   - C → G (6) → **Total: 3 + 6 = 9** (Same as Batuu → D → G)
   
   🔹 **Updated Path Costs:**  
   - Batuu → D → C → E (4) ✅
   - Batuu → D → G (9)

3. **From E (4)**:
   - E → H (5) → **Total: 4 + 5 = 9**
   - E → I (1) → **Total: 4 + 1 = 5**

   🔹 **Updated Path Costs:**  
   - Batuu → D → C → E → I (5) ✅
   - Batuu → D → C → E → H (9)

4. **From I (5)**:
   - I → J (3) → **Total: 5 + 3 = 8**
   - I → L (6) → **Total: 5 + 6 = 11**

   🔹 **Updated Path Costs:**  
   - Batuu → D → C → E → I → J (8) ✅
   - Batuu → D → C → E → I → L (11)

5. **From J (8)**:
   - J → K (2) → **Total: 8 + 2 = 10**
   
   🔹 **Updated Path Costs:**  
   - Batuu → D → C → E → I → J → K (10) ✅

6. **From K (10)**:
   - K → O (9) → **Total: 10 + 9 = 19**

   🔹 **Updated Path Costs:**  
   - Batuu → D → C → E → I → J → K → O (19) ✅

7. **From O (19)**:
   - O → S (11) → **Total: 19 + 11 = 30**
   
   🔹 **Updated Path Costs:**  
   - Batuu → D → C → E → I → J → K → O → S (30) ✅

8. **From S (30)**:
   - S → Jedha (8) → **Total: 30 + 8 = 38** ✅

---

### **Step 3: Final Shortest Path**
🚀 **Shortest Path from Batuu to Jedha avoiding N:**  
✅ **Batuu → D → C → E → I → J → K → O → S → Jedha**  
**Total Cost: 38**

---

### **Final Answer**
**The shortest path from Batuu to Jedha (while avoiding N) is:**  
🛤 **Batuu → D → C → E → I → J → K → O → S → Jedha**  
**Total Path Cost: 38** ✅  


```
Mission 6
Issue: The Resistance is determined to seek revenge for the damage the Empire has caused with all of its attacks.

You are tasked with gathering secret information from the Dark Side network servers that can be used to launch network attacks against the Empire.

You have captured some of the Dark Side's encrypted wireless internet traffic in the following PCAP: Dark Side PCAPLinks to an external site..

Your Mission:

Figure out the Dark Side's secret wireless key by using Aircrack-ng.
hint
This is a more challenging encrypted wireless traffic using WPA.

To decrypt, you will need to use a wordlist (-w) such as rockyou.txt.
Use the Dark Side's key to decrypt the wireless traffic in Wireshark.
hint
The format for the key to decrypt wireless is <Wireless_key>:<SSID>.

Once you have decrypted the traffic, figure out the Dark Side's host IP addresses and MAC addresses (examine the decrypted ARP traffic).

Document these IP and MAC addresses, as the Resistance will use them to launch a retaliatory attack.
```

```

kaziislam@mac bin % ./aircrack-ng ~/Downloads/Darkside.pcap 
Reading packets, please wait...
Opening /Users/kaziislam/Downloads/Darkside.pcap
Read 586 packets.

   #  BSSID              ESSID                     Encryption

   1  00:0B:86:C2:A4:85  linksys                   WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening /Users/kaziislam/Downloads/Darkside.pcap
Read 586 packets.

1 potential targets

Please specify a dictionary (option -w).


kaziislam@mac bin % ./aircrack-ng -w ~/Downloads/rockyou.txt -b 00:0B:86:C2:A4:85 ~/Downloads/Darkside.pcap 
Reading packets, please wait...
Opening /Users/kaziislam/Downloads/Darkside.pcap
Read 586 packets.

1 potential targets



                               Aircrack-ng 1.7 

      [00:00:01] 7297/10303727 keys tested (13655.63 k/s) 

      Time left: 12 minutes, 34 seconds                          0.07%

                          KEY FOUND! [ dictionary ]


      Master Key     : 5D F9 20 B5 48 1E D7 05 38 DD 5F D0 24 23 D7 E2 
                       52 22 05 FE EE BB 97 4C AD 08 A5 2B 56 13 ED E2 

      Transient Key  : 97 97 AA C7 82 8F 52 F0 EB C7 05 04 C0 A3 7E 31 
                       7C B3 DF 24 D5 25 85 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 6D 45 F3 53 8E AD 8E CA 55 98 C2 60 EE FE 6F 51 


kaziislam@mac bin % 
```


### Reviewing Key Details from ARP Packets

#### Packet No. 312
- **Source MAC Address:** 00:13:ce:55:98:ef
- **Destination MAC Address:** ff:ff:ff:ff:ff:ff (Broadcast)
- **Sender IP Address:** 172.16.0.101
- **Target IP Address:** 172.16.0.1
- **Info:** ARP request: "Who has 172.16.0.1? Tell 172.16.0.101"

#### Packet No. 314
- **Source MAC Address:** 00:13:ce:55:98:ef
- **Destination MAC Address:** ff:ff:ff:ff:ff:ff (Broadcast)
- **Sender IP Address:** 172.16.0.101
- **Target IP Address:** 172.16.0.1
- **Info:** ARP request: "Who has 172.16.0.1? Tell 172.16.0.101"

#### Packet No. 315
- **Source MAC Address:** 00:0f:66:e3:e4:01
- **Destination MAC Address:** 00:13:ce:55:98:ef
- **Sender IP Address:** 172.16.0.1
- **Target IP Address:** 172.16.0.101
- **Info:** ARP reply: "172.16.0.1 is at 00:0f:66:e3:e4:01"

### Summary of Findings:
- **Hosts Identified:**
  - **MAC Address:** 00:13:ce:55:98:ef
    - **IP Address:** 172.16.0.101
  - **MAC Address:** 00:0f:66:e3:e4:01
    - **IP Address:** 172.16.0.1
  - **Broadcast Address:** ff:ff:ff:ff:ff:ff

### Actionable Information for the Resistance:
- **Confirmed Host IP and MAC Addresses:**
  - **Device 1:** 172.16.0.101 (MAC: 00:13:ce:55:98:ef)
  - **Device 2:** 172.16.0.1 (MAC: 00:0f:66:e3:e4:01)

These devices are part of the Dark Side's network. The Resistance can use this information to understand the network layout and plan further actions.


```
Mission 7
Issue: As a thank you for saving the Galaxy, the Resistance wants to send you a secret message!

Your Mission:

View the DNS record from Mission 4. The Resistance provided you with a hidden message in the TXT record. Follow the steps included in the message.

note
A backup option is provided in the TXT record (as a website) in case the main Telnet site is unavailable.

Hint: Telnet might require switching to the IPv6 version of the site. Use man to research how to do this.
Take notes (or a screenshot) of the results.
```

```
nslookup -type=txt princessleia.site
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
princessleia.site	text = "Run the following in a command line: telnet towel.blinkenlights.nl or as a backup access in a browser: www.asciimation.co.nz"

Authoritative answers can be found from:
```

Excellent! You've retrieved the TXT record, which gives you two options:

1.  `telnet towel.blinkenlights.nl`
2.  `www.asciimation.co.nz`

Let's try the Telnet option first, as it's often the intended path in CTFs:

```bash
telnet towel.blinkenlights.nl
```

This should connect you to a text-based animation (likely Star Wars-related, given the theme).  If that doesn't work (sometimes these public Telnet servers are overloaded or down), try the backup website:

```
www.asciimation.co.nz
```

This website should also display a text-based animation.

**Important:** The output of either of these commands (Telnet or website) is the secret message you're looking for!  Make sure to capture it (screenshot or copy/paste).  That's the flag for this mission.
