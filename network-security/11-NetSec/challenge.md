Part 1: Snort Rules
Snort Rule Analysis
Questions 1–6 will focus on Snort. Use the two provided Snort rules to answer these questions:

Snort Rule #1

alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
Snort Rule #2

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)


Part 2: "Drop Zone" Lab
Your company hosts a web server that accepts online reservations and credit card payments. As a result, the company must comply with PCI/DSS regulations that require businesses who accept online credit card payments to have a firewall in place to protect personally identifiable information (PII).

Your network has been under attack from the following three IPs: 10.208.56.23, 135.95.103.76, and 76.34.169.118. You have decided to add these IPs to the drop zone within your firewall.

The first requirement of PCI/DSS regulations is to protect your system with firewalls. "Properly configured firewalls protect your card data environment. Firewalls restrict incoming and outgoing network traffic through rules and criteria configured by your organization." —
PCI DSS Quick Reference GuideLinks to an external site.

Set Up
For this lab, use your netsec virtual machine.

Once logged in, launch the firewalld and ufw docker containers, and create an interactive session with the firewalld container with the following command:
docker exec -it firewalld bash

Be sure to run the following as soon as you connect to the firewalld container
sudo sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw

`

Instructions
The senior security manager has drafted configuration requirements for your organization with the following specification:

You need to configure zones that will segment each network according to service type.

public Zone
Services: HTTP, HTTPS, POP3, SMTP
Interface: ETH0
web Zone
Source IP: 201.45.34.126
Services: HTTP
Interface: ETH1
sales Zone
Source IP: 201.45.15.48
Services: HTTPS
Interface: ETH2
mail Zone
Source IP: 201.45.105.12
Services: SMTP, POP3
Interface: ETH3
You also need to drop all traffic from the following blacklisted IPs:

10.208.56.23
135.95.103.76
76.34.169.118
Reference: https://manpages.debian.org/testing/firewalld/firewall-cmd.1.en.htmlLinks to an external site.


```

sudo firewall-cmd --zone=web --add-source=201.45.34.126 --permanent
sudo firewall-cmd --zone=sales --add-source=201.45.15.48 --permanent
firewall-cmd --zone=mail --add-source=201.45.105.12


sudo firewall-cmd --zone=drop --add-source=10.208.56.23 --permanent
sudo firewall-cmd --zone=drop --add-source=135.95.103.76 --permanent
sudo firewall-cmd --zone=drop --add-source=76.34.169.118 --permanent

firewall-cmd --reload



```


Uninstall ufw
Before getting started, verify that you do not have any instances of UFW running. This will avoid conflicts with your firewalld service. This also ensures that firewalld will be your default firewall.

```

```

Run the command that removes any running instance of UFW.
Enable and start firewalld.
By default, the firewalld service should be running. If not, run the commands that enable and start firewalld upon boots and reboots.

```
service firewalld status
```

note
This will ensure that firewalld remains active after each reboot.

Confirm that the service is running.
Run the command that checks whether the firewalld service is up and running.
List all firewall rules currently configured.
Next, lists all currently configured firewall rules. This will give you an idea of what's currently configured and ensuring you don’t duplicate work that’s already done.

Run the command that lists all currently configured firewall rules.

Take note of what zones and settings are configured. You many need to remove unneeded services and settings.

List all supported service types that can be enabled.
Run the command that lists all currently supported services to find out whether the service you need is available.

```
sudo firewall-cmd --get-services
sudo firewall-cmd --get-zones

```

Notice that the home and drop zones are created by default.

Zone views.
Run the command that lists all currently configured zones.

```
firewall-cmd --list-all-zones
```

Notice that the public and drop zones are created by default. Therefore, you will need to create zones for web, sales, and mail.

Create zones for web, sales and mail.
Run the commands that create web, sales, and mail zones.

```
sudo firewall-cmd --new-zone=web --permanent
sudo firewall-cmd --new-zone=sales --permanent
sudo firewall-cmd --new-zone=mail --permanent
```


hint
If needed, refer to the manpage in the Instructions section for assistance.

Remember to reload the firewalld service to apply your new settings before moving on.

Set the zones to their designated interfaces.
Run the commands that set your eth interfaces to your zones.


```

sudo firewall-cmd --zone=public --change-interface=eth0 --permanent
sudo firewall-cmd --zone=web --change-interface=eth1 --permanent
sudo firewall-cmd --zone=sales --change-interface=eth2 --permanent
sudo firewall-cmd --zone=mail --change-interface=eth3 --permanent
```


Use the configurations provided at the beginning of the instructions.
Add services to the active zones.
Run the commands that add services to the public zone, the web zone, the sales zone, and the mail zone.

```
sudo firewall-cmd --zone=public --add-service=http --permanent
sudo firewall-cmd --zone=public --add-service=https --permanent
sudo firewall-cmd --zone=public --add-service=pop3 --permanent
sudo firewall-cmd --zone=public --add-service=smtp --permanent
sudo firewall-cmd --zone=web --add-service=http --permanent
sudo firewall-cmd --zone=sales --add-service=https --permanent
sudo firewall-cmd --zone=mail --add-service=smtp --permanent
sudo firewall-cmd --zone=mail --add-service=pop3 --permanent
```

Use the configurations provided at the beginning of the instructions.
Add your adversaries to the drop zone.
Run the command that will add all current and any future blacklisted IPs to the drop zone.

```
sudo firewall-cmd --zone=web --add-source=201.45.34.126 --permanent
sudo firewall-cmd --zone=sales --add-source=201.45.15.48 --permanent
firewall-cmd --zone=mail --add-source=201.45.105.12

sudo firewall-cmd --zone=drop --add-source=10.208.56.23 --permanent
sudo firewall-cmd --zone=drop --add-source=135.95.103.76 --permanent
sudo firewall-cmd --zone=drop --add-source=76.34.169.118 --permanent

firewall-cmd --reload

```

Make rules permanent, then reload them.
It's good practice to ensure that your firewalld installation remains nailed up and retains its services across reboots. This helps ensure that the network remains secure after unplanned outages such as power failures.

Run the command that reloads the firewalld configurations and writes it to memory.
View active zones.
Now, provide truncated listings of all currently active zones. This is a good time to verify your zone settings.

```
<pre>firewall-cmd --get-active-zones
drop
  sources: 10.208.56.23 135.95.103.76 76.34.169.118
mail
  interfaces: eth3
public
  interfaces: eth0
sales
  interfaces: eth2
  sources: 201.45.15.48
web
  interfaces: eth1
  sources: 201.45.34.126</pre>
```

Run the command that displays all zone services.
Block an IP address.
Use a rich-rule that blocks the IP address 138.138.0.3 on your public zone.

```
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject'

```

Block Ping/ICMP Requests
Harden your network against ping scans by blocking icmp ehco replies.

```
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" protocol value="icmp" reject'
```

Run the command that blocks pings and icmp requests in your public zone.
Rule Check
Now that you've set up your brand new firewalld installation, it's time to verify that all of the settings have taken effect.

Run the command that lists all of the rule settings. Run one command at a time for each zone.

Are all of the rules in place? If not, then go back and make the necessary modifications before checking again.

Congratulations! By completing the previous commands, you have successfully configured and deployed a fully comprehensive firewalld installation.

Part 3: IDS, IPS, DiD, and Firewalls
Questions 22–34 will focus on IDS, IPS, Defense-in-Depth, and firewall architectures.



