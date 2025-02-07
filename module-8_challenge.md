Instructions
Rocking your Network
You are hired by RockStar Corporation as a network security analyst.

RockStar Corp recently built a new office in Hollywood, California. You are tasked with completing a network vulnerability assessment of the office.

You will complete several steps to analyze the Hollywood network and then provide RockStar Corp a summary of your findings.

RockStar Corp is also concerned that a malicious hacker may have infiltrated its Hollywood office. You will need to determine whether there is anything suspicious in your findings.

Files Required
RockStar Corp has provided you with:

A list of its network assets: RockStar Corp Server ListLinks to an external site.
The following instructions to scan its network.
Instructions
Follow the instructions to work through the four phases of the network assessment. As you work, take note of:
The steps and commands used to complete the tasks
Any network vulnerabilities discovered
Any findings associated with a hacker
Recommended mitigation strategy
The OSI layer(s) your findings involve
You will use your notes to answer the questions in this quiz.

IMPORTANT: Please review your answers carefully before submitting to ensure they are free of spelling and spacing errors. Incorrect spelling or spacing syntax will be marked as incorrect answers.

Topics Covered in This Assignment
Subnetting
CIDR
IP addresses
ping
OSI model and its layers
Protocols
Ports
Wireshark
PCAP analysis
DNS
HTTP
ARP
SYN scan
TCP
nslookup
Network vulnerability assessments
Network vulnerability mitigation
Network Vulnerability Assessment Instructions
Use your Web Lab virtual machine for this assignment.

Phase 1: "I'd Like to Teach the World to Ping"
You have been provided a list of network assets belonging to RockStar Corp. Ping the network assets for only the Hollywood office.

Important: You will need to run this activity from your local machine, and NOT the web lab.
Determine the IPs for the Hollywood office and run ping against the IP ranges to determine which IP(s) are accepting connections.
RockStar Corp doesn't want any of its servers, even if they are up, to indicate that they are accepting connections.
Use ping <IP Address> and ignore any results that say "Request timed out."
If any of the IP addresses send back a reply, press Ctrl+C to stop sending requests.
Hint: Try to ping a few IPs individually from your local desktop (outside of the web lab), such as:
15.199.95.91
15.199.94.91
161.35.96.20
Take note of the relevant information for Phase 1, including the ping command(s) used, a summary of the results (including which IPs accept connections and which do not), and which OSI layer(s) your findings involve.

Phase 2: "Some SYN for Nothin'"
Using your findings from Phase 1, determine which ports are open.

Run a SYN scan against the IP(s) accepting connections. Follow the instructions in the following SYN Scan Instructions section.

Using the results of the SYN scan, determine which ports are accepting connections.

Fill out the relevant information for Phase 2 in your submission file.

SYN Scan Instructions

What is Nmap?

Nmap is a free networking scanning tool available for Linux distributions.

Security professionals use Nmap to determine what devices are running on a network and to find open ports to determine potential security vulnerabilities.

Nmap has many capabilities and commands that can be run. Refer to this Nmap cheat sheetLinks to an external site. for reference.

For this activity, we will specifically focus on Nmap's ability to run a SYN scan.

You already know that a SYN scan is an automated method to check for the states of ports on a network. Nmap is simply a tool that can automate this task.
To run a SYN scan:

Open the terminal in your Linux machine.

Use the following command to run a SYN scan:

nmap -sS <IP Address>

For example, if you want to run a SYN scan against the server IP 74.207.244.221, run nmap -sS 74.207.244.221 and press Enter.

This will scan the most common 1,000 ports.

After this runs for several minutes, it should return a result similar to the following that depicts the state of the ports on that server:

Starting Nmap 7.70 (https://nmap.org) at 2019-08-14 11:51 EDT
Nmap scan report for li86-221.members.linode.com (74.207.244.221)
Host is up (1.4s latency).
Not shown: 988 closed ports
PORT    STATE    SERVICE
22/tcp  open     ssh
25/tcp  filtered smtp
110/tcp open     pop3
113/tcp filtered ident
135/tcp filtered msrpc
139/tcp filtered netbios-ssn
143/tcp open     imap
445/tcp filtered microsoft-ds
465/tcp open     smtps
587/tcp open     submission
993/tcp open     imaps
995/tcp open     pop3s
The results show the port number, TCP, or UDP, the state of the port, and the service or protocol for the ports that are either open or filtered (i.e., stopped by a firewall).

Closed ports are not shown, as indicated on the line Not shown: 988 closed ports.

For the purpose of this exercise, document in your submission file which ports are open on the RockStar Corp server and which OSI layer SYN scans run on.

Phase 3: "I Feel a DNS Change Comin' On"
Using your findings from Phase 2, determine whether you can access the server(s) that accept connections.

RockStar Corp typically uses the same default username and password for most of its servers, so try this first:

Username: jimi

Password: hendrix

Try to figure out which port or service is used for remote system administration. Then, using these credentials, attempt to log in to the IP(s) that responded to pings in Phase 1.

RockStar Corp recently reported that it is unable to access rollingstone.com in the Hollywood office. Sometimes, when they try to access the website, a different, unusual website comes up.

While logged into the RockStar server from the previous step, determine whether something was modified on this system that affects viewing rollingstone.com in the browser. When you successfully find the configuration file, record the entry that is set to rollingstone.com.

Terminate your SSH session to the rollingstone.com server, and use nslookup to determine the real domain of the IP address that you found in the previous step.

note
nslookup is a command-line utility that can work in Windows or Linux systems. It is designed to query Domain Name System records. You can use PowerShell or MacOS/Linux terminal to run nslookup.

To run nslookup, enter the following on the command line:

nslookup <IP Address> to find the domain associated to an IP address

OR

nslookup <domain name> to find the IP address associated with a domain

You'll know you've found the right domain if it begins with unknown.

Add your findings to your submission file.

Phase 4: "ShARP Dressed Man"
Within the RockStar server that you SSH'd into and in the same directory as the configuration file from Phase 3, the hacker left a note about where they stored some packet captures.

View the file to find out where to recover the packet captures.

These packets were captured from the activity in the Hollywood office.

Use Wireshark to analyze this PCAP file and determine whether there was any suspicious activity that could be attributed to a hacker.

Record and identify your findings (e.g., OSI layers, protocols, IP addresses, and MAC addresses).

hint
Focus on the ARP and HTTP protocols. Recall the different types of HTTP request methods, and be sure to examine the contents of these packets thoroughly.