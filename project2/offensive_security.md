```markdown
# Offensive Security Reference Guide

This document provides a comprehensive list of offensive security topics, tools, and techniques covered in the Offensive Security Unit. Use this as a quick reference for future penetration testing engagements.

---

## Penetration Testing Topics
- **OSINT**: Open Source Intelligence gathering to collect publicly available information about a target.
- **MITRE Framework**: A framework for understanding and mapping adversary tactics and techniques.
- **Enumeration**: Identifying users, services, and resources on a target system or network.
- **Port Scanning**: Discovering open ports and services on a target system.
- **Exploitation**: Leveraging vulnerabilities to gain unauthorized access to a system.
- **Shells**:
  - **Bind Shell**: The target machine opens a port and waits for the attacker to connect.
  - **Reverse Shell**: The target machine connects back to the attacker.
- **Lateral Movement**: Moving between systems within a network using compromised credentials or exploits.
- **Persistence**: Maintaining access to a compromised system over time.

---

## Web Application Vulnerabilities
- **Injection Vulnerabilities**:
  - **SQL Injection**: Exploiting improperly sanitized SQL queries to manipulate databases.
  - **XSS (Cross-Site Scripting)**:
    - **Stored XSS**: Malicious scripts are stored on the server and executed when users access the page.
    - **Reflected XSS**: Malicious scripts are reflected off a web server and executed in the user's browser.
- **Back-End Component Vulnerabilities**: Exploiting weaknesses in server-side components.
- **Directory Traversal**: Accessing restricted directories and files on a server.
- **LFI (Local File Inclusion)**: Including local files on the server in the web application.
- **RFI (Remote File Inclusion)**: Including remote files in the web application.

---

## Authentication Vulnerabilities
- **Session Management**: Exploiting weaknesses in session handling mechanisms.
- **Brute-Force Attacks**: Attempting multiple username and password combinations to gain access.

---

## Penetration Testing Tools
- **Metasploit and Meterpreter**: A framework for exploitation and post-exploitation activities.
- **Nmap**: A network scanning tool for discovering hosts, services, and vulnerabilities.
- **Recon-ng**: A reconnaissance framework for gathering OSINT.
- **Shodan**: A search engine for discovering internet-connected devices and services.
- **SearchSploit**: A tool for searching and using exploits from the Exploit-DB database.
- **netcat**: A versatile networking tool for creating connections, transferring data, and setting up shells.

---

## Web Application Testing Tools
- **Burp Suite**: A comprehensive tool for testing web application security, including intercepting requests, scanning for vulnerabilities, and exploiting weaknesses.

---

By referencing this guide, you can quickly recall the key topics, tools, and techniques covered in the Offensive Security Unit. Use this knowledge responsibly and ethically in your penetration testing engagements.
```
