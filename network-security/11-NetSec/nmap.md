```markdown
# Nmap Usage and Scenarios

As a security analyst, you may encounter situations where logs and files are missing from your system, and timestamps on logs and files have been manipulated. Such incidents often indicate that an attacker has gained unauthorized access to your network. In one such scenario, it was discovered that an attacker had entered the network through port 3389, which is used for Remote Desktop Protocol (RDP). A network scan with Nmap could have identified that the port was open, along with other open ports, potentially preventing the attack.

## Information Gathered by Network Scans

By performing network scans, attackers can gather the following information:
- Name and version of the operating system (OS fingerprinting)
- All open and closed ports
- All filtered ports (ports behind a firewall)
- Types of services running on specific ports (service and daemon names)

## Firewalking

Firewalking is a type of reconnaissance that uses network security analysis to determine which Layer 4 protocols a specific firewall will allow.

## Nmap Demo Setup

In this demo, we'll use our `firewalld` container to perform scans against our UFW firewall. The scenario is as follows:
Your security manager has installed a brand new, fully configured firewall and would like you to test it using Nmap. You will use various fingerprinting techniques to reveal the type of operating system, services, daemons, and protocols that are currently running. You will also test to see which ports are open, closed, and filtered.

## Steps to Perform Nmap Scans

### 1. Perform OS Fingerprinting and Scan Ports 1 through 500

- **Command**: `nmap -O -p 1-500 --osscan-guess`
- **Description**: This command performs OS fingerprinting and scans ports 1 through 500.
- **Example**:
  ```bash
  nmap -O -p 1-500 --osscan-guess <target_ip>
  ```

### 2. Print the OS Type and Version

- **Command**: `uname -a`
- **Description**: This command prints the OS type and version.
- **Example**:
  ```bash
  uname -a
  ```

### 3. Enumerate Service Type

- **Command**: `nmap -sV`
- **Description**: This command enumerates the service type.
- **Example**:
  ```bash
  nmap -sV <target_ip>
  ```

### 4. Perform OS Fingerprinting Using Fast Execution

- **Command**: `nmap -A -T4`
- **Description**: This command performs OS fingerprinting using fast execution.
- **Example**:
  ```bash
  nmap -A -T4 <target_ip>
  ```

### 5. Perform an IP Protocol Scan

- **Command**: `nmap -sO`
- **Description**: This command performs an IP protocol scan.
- **Example**:
  ```bash
  nmap -sO <target_ip>
  ```

### 6. Perform Device and Port Enumeration

- **Command**: `nmap -sU -F`
- **Description**: This command performs device and port enumeration.
- **Example**:
  ```bash
  nmap -sU -F <target_ip>
  ```

### 7. Enumerate the Type of Firewall in Use

- **Command**: `nmap -sA`
- **Description**: This command enumerates the type of firewall in use.
- **Example**:
  ```bash
  nmap -sA <target_ip>
  ```

### 8. Use CVE site - https://cve.mitre.org/ to figure out any open vulnerabilities

By following these steps, you can effectively use Nmap to gather detailed information about the target system, including open ports, services, operating system details, and firewall configurations. This information is crucial for identifying potential vulnerabilities and securing your network against unauthorized access.

```