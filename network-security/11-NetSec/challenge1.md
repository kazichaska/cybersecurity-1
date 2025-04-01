```markdown
# Challenge: Network Security and Firewalls

## Part 1: Snort Rules

### Snort Rule Analysis

Questions 1–6 will focus on Snort. Use the two provided Snort rules to answer these questions:

#### Snort Rule #1

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
```

#### Snort Rule #2

```snort
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
```

## Part 2: "Drop Zone" Lab

In this lab exercise, you will assume the role of a junior security administrator at an indoor skydiving company called Drop Zone.

### Scenario

Your company hosts a web server that accepts online reservations and credit card payments. As a result, the company must comply with PCI/DSS regulations that require businesses who accept online credit card payments to have a firewall in place to protect personally identifiable information (PII).

Your network has been under attack from the following three IPs: `10.208.56.23`, `135.95.103.76`, and `76.34.169.118`. You have decided to add these IPs to the drop zone within your firewall.

### Set Up

For this lab, use your netsec virtual machine.

Once logged in, launch the firewalld and ufw docker containers, and create an interactive session with the firewalld container with the following command:
```bash
docker exec -it firewalld bash
```

Be sure to run the following as soon as you connect to the firewalld container:
```bash
sudo sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
```

### Instructions

The senior security manager has drafted configuration requirements for your organization with the following specification:

#### Configure Zones

You need to configure zones that will segment each network according to service type.

- **public Zone**
  - Services: HTTP, HTTPS, POP3, SMTP
  - Interface: ETH0
- **web Zone**
  - Source IP: 201.45.34.126
  - Services: HTTP
  - Interface: ETH1
- **sales Zone**
  - Source IP: 201.45.15.48
  - Services: HTTPS
  - Interface: ETH2
- **mail Zone**
  - Source IP: 201.45.105.12
  - Services: SMTP, POP3
  - Interface: ETH3

#### Drop All Traffic from Blacklisted IPs

- `10.208.56.23`
- `135.95.103.76`
- `76.34.169.118`

### Steps

1. **Uninstall UFW**
   - Run the command that removes any running instance of UFW.
     ```bash
     sudo apt-get remove ufw
     ```

2. **Enable and Start firewalld**
   - Run the commands that enable and start firewalld upon boots and reboots.
     ```bash
     sudo systemctl enable firewalld
     sudo systemctl start firewalld
     ```

3. **Confirm firewalld is Running**
   - Run the command that checks whether the firewalld service is up and running.
     ```bash
     sudo firewall-cmd --state
     ```

4. **List All Firewall Rules**
   - Run the command that lists all currently configured firewall rules.
     ```bash
     sudo firewall-cmd --list-all
     ```

5. **List All Supported Service Types**
   - Run the command that lists all currently supported services.
     ```bash
     sudo firewall-cmd --get-services
     ```

6. **List All Configured Zones**
   - Run the command that lists all currently configured zones.
     ```bash
     sudo firewall-cmd --get-zones
     ```

7. **Create Zones for web, sales, and mail**
   - Run the commands that create web, sales, and mail zones.
     ```bash
     sudo firewall-cmd --permanent --new-zone=web
     sudo firewall-cmd --permanent --new-zone=sales
     sudo firewall-cmd --permanent --new-zone=mail
     sudo firewall-cmd --reload
     ```

8. **Set Zones to Their Designated Interfaces**
   - Run the commands that set your eth interfaces to your zones.
     ```bash
     sudo firewall-cmd --zone=public --change-interface=eth0 --permanent
     sudo firewall-cmd --zone=web --change-interface=eth1 --permanent
     sudo firewall-cmd --zone=sales --change-interface=eth2 --permanent
     sudo firewall-cmd --zone=mail --change-interface=eth3 --permanent
     sudo firewall-cmd --reload
     ```

9. **Add Services to the Active Zones**
   - Run the commands that add services to the public zone, the web zone, the sales zone, and the mail zone.
     ```bash
     sudo firewall-cmd --zone=public --add-service=http --permanent
     sudo firewall-cmd --zone=public --add-service=https --permanent
     sudo firewall-cmd --zone=public --add-service=pop3 --permanent
     sudo firewall-cmd --zone=public --add-service=smtp --permanent
     sudo firewall-cmd --zone=web --add-service=http --permanent
     sudo firewall-cmd --zone=sales --add-service=https --permanent
     sudo firewall-cmd --zone=mail --add-service=smtp --permanent
     sudo firewall-cmd --zone=mail --add-service=pop3 --permanent
     sudo firewall-cmd --reload
     ```

10. **Add Adversaries to the Drop Zone**
    - Run the command that will add all current and any future blacklisted IPs to the drop zone.
      ```bash
      sudo firewall-cmd --zone=drop --add-source=10.208.56.23 --permanent
      sudo firewall-cmd --zone=drop --add-source=135.95.103.76 --permanent
      sudo firewall-cmd --zone=drop --add-source=76.34.169.118 --permanent
      sudo firewall-cmd --reload
      ```

11. **Make Rules Permanent and Reload**
    - Run the command that reloads the firewalld configurations and writes it to memory.
      ```bash
      sudo firewall-cmd --runtime-to-permanent
      sudo firewall-cmd --reload
      ```

12. **View Active Zones**
    - Run the command that displays all zone services.
      ```bash
      sudo firewall-cmd --get-active-zones
      ```

13. **Block an IP Address**
    - Use a rich-rule that blocks the IP address `138.138.0.3` on your public zone.
      ```bash
      sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject' --permanent
      sudo firewall-cmd --reload
      ```

14. **Block Ping/ICMP Requests**
    - Run the command that blocks pings and icmp requests in your public zone.
      ```bash
      sudo firewall-cmd --zone=public --add-icmp-block=echo-request --permanent
      sudo firewall-cmd --reload
      ```

15. **Rule Check**
    - Run the command that lists all of the rule settings. Run one command at a time for each zone.
      ```bash
      sudo firewall-cmd --zone=public --list-all
      sudo firewall-cmd --zone=web --list-all
      sudo firewall-cmd --zone=sales --list-all
      sudo firewall-cmd --zone=mail --list-all
      ```

Congratulations! By completing the previous commands, you have successfully configured and deployed a fully comprehensive firewalld installation.

## Part 3: IDS, IPS, DiD, and Firewalls

Questions 22–34 will focus on IDS, IPS, Defense-in-Depth, and firewall architectures.

### IDS (Intrusion Detection System)

An IDS is a passive system that monitors network traffic for suspicious activity and generates alerts. It does not take action to block or prevent the detected threats.

### IPS (Intrusion Prevention System)

An IPS is an active system that monitors network traffic for suspicious activity and takes action to block or prevent the detected threats in real-time.

### Defense-in-Depth (DiD)

Defense-in-Depth is a security strategy that employs multiple layers of defense to protect an organization's assets. It includes measures such as firewalls, IDS/IPS, antivirus software, and security policies.

### Firewalls

Firewalls are security devices or software that monitor and control incoming and outgoing network traffic based on predefined security rules. They act as a barrier between a trusted internal network and untrusted external networks.

```