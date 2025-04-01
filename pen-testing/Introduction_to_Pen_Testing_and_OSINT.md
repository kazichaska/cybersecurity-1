```markdown
# Introduction to Pen Testing and OSINT

## Understand the Role of a Pen Tester in Assessing a Business's Security

A penetration tester (pen tester) is a cybersecurity professional who simulates cyberattacks on a business's systems, networks, and applications to identify vulnerabilities and weaknesses. The goal is to assess the security posture of the organization and provide recommendations for improvement.

### Key Responsibilities

- **Vulnerability Assessment**: Identifying and evaluating security vulnerabilities in systems and applications.
- **Exploitation**: Attempting to exploit identified vulnerabilities to determine their impact.
- **Reporting**: Documenting findings and providing recommendations for remediation.
- **Compliance**: Ensuring that the organization meets security standards and regulatory requirements.

### Example

- **Scenario**: A pen tester is hired to assess the security of a company's web application.
  - **Vulnerability Assessment**: The pen tester scans the web application for common vulnerabilities such as SQL injection and cross-site scripting (XSS).
  - **Exploitation**: The pen tester attempts to exploit identified vulnerabilities to gain unauthorized access to sensitive data.
  - **Reporting**: The pen tester documents the findings and provides recommendations for fixing the vulnerabilities.
  - **Compliance**: The pen tester ensures that the web application complies with industry security standards.

## Collect Domain Information by Using OSINT Techniques and Tools

Open Source Intelligence (OSINT) involves collecting information from publicly available sources to gather intelligence about a target domain. OSINT techniques and tools can help identify potential security risks.

### Google Hacking

Google hacking involves using advanced search operators to find sensitive information exposed on the internet.

### Example

- **Search Query**:
  ```plaintext
  site:example.com filetype:pdf
  ```
  - **Explanation**: This query searches for PDF files on the domain `example.com`.

### Shodan

Shodan is a search engine for internet-connected devices. It can be used to discover information about servers, routers, webcams, and other devices.

### Example

- **Search Query**:
  ```plaintext
  hostname:example.com
  ```
  - **Explanation**: This query searches for devices with the hostname `example.com`.

### Certificate Transparency

Certificate transparency logs provide information about SSL/TLS certificates issued for a domain. This can help identify subdomains and potential security issues.

### Example

- **Tool**: [crt.sh](https://crt.sh/)
  - **Search Query**: `example.com`
  - **Explanation**: This query searches for SSL/TLS certificates issued for the domain `example.com`.

## Use Shodan and Recon-ng to Discover Domain Server Information

### Shodan

Shodan can be used to discover detailed information about domain servers, including open ports, services, and vulnerabilities.

### Example

- **Search Query**:
  ```plaintext
  hostname:example.com
  ```
  - **Explanation**: This query searches for devices with the hostname `example.com`.

- **Results**:
  ```plaintext
  IP: 192.0.2.1
  Open Ports: 80, 443
  Services: HTTP, HTTPS
  ```

### Recon-ng

Recon-ng is a powerful reconnaissance framework that automates the process of gathering information about a target domain.

### Steps

1. **Install Recon-ng**:
   - ```bash
     git clone https://github.com/lanmaster53/recon-ng.git
     cd recon-ng
     pip install -r REQUIREMENTS
     ```

2. **Start Recon-ng**:
   - ```bash
     ./recon-ng
     ```

3. **Create a Workspace**:
   - ```plaintext
     workspaces create example
     ```

4. **Add a Domain**:
   - ```plaintext
     add domains example.com
     ```

5. **Run Modules**:
   - ```plaintext
     modules load recon/domains-hosts/shodan_hostname
     run
     ```

### Example

- **Command**:
  ```plaintext
  modules load recon/domains-hosts/shodan_hostname
  run
  ```
  - **Explanation**: This command loads the Shodan module and runs it to gather information about the domain `example.com`.

By understanding these concepts and using these tools, you can effectively gather intelligence about a target domain and assess its security posture.

```