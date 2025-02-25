```markdown
# firewalld Commands

## Start the Firewall

- **Command**: `sudo /etc/init.d/firewalld start`
- **Description**: Starts the firewalld service.
- **Example**:
  ```bash
  sudo /etc/init.d/firewalld start
  ```

## Create, Modify, and Delete Rules

- **Command**: `sudo firewall-cmd`
- **Description**: Used to create, modify, and delete firewall rules.
- **Example**: Allow HTTP service.
  ```bash
  sudo firewall-cmd --permanent --add-service=http
  sudo firewall-cmd --reload
  ```

## List All Configured Zones

- **Command**: `sudo firewall-cmd --list-all-zones`
- **Description**: Lists all the currently configured zones.
- **Example**:
  ```bash
  sudo firewall-cmd --list-all-zones
  ```

## Bind Zones to Physical Interfaces

- **Command**: `sudo firewall-cmd --zone=<zone> --change-interface=<interface>`
- **Description**: Binds a zone to a physical interface.
- **Example**: Bind the `work` zone to the `eth1` interface.
  ```bash
  sudo firewall-cmd --zone=work --change-interface=eth1
  ```

## List All Active Rules in a Zone

- **Command**: `sudo firewall-cmd --zone=<zone> --list-all`
- **Description**: Lists all active rules in a specified zone.
- **Example**: List all active rules in the `public` zone.
  ```bash
  sudo firewall-cmd --zone=public --list-all
  ```

## List All Configured Services

- **Command**: `sudo firewall-cmd --get-services`
- **Description**: Lists all the currently configured services.
- **Example**:
  ```bash
  sudo firewall-cmd --get-services
  ```

## Configure Rules with More Detailed Options

- **Command**: `sudo firewall-cmd --permanent --add-rich-rule='<rule>'`
- **Description**: Adds a rich rule with more detailed options.
- **Example**: Allow SSH from a specific IP address.
  ```bash
  sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.100" service name="ssh" accept'
  sudo firewall-cmd --reload
  ```

## Block Ping Requests

- **Command**: `sudo firewall-cmd --permanent --add-icmp-block=<type>`
- **Description**: Blocks ICMP requests of a specified type.
- **Example**: Block ping requests.
  ```bash
  sudo firewall-cmd --permanent --add-icmp-block=echo-request
  sudo firewall-cmd --reload
  ```

```