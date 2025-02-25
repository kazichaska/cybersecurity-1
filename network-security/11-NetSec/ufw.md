```markdown
# UFW (Uncomplicated Firewall) Commands

## Reset UFW Rules

- **Command**: `sudo ufw reset`
- **Description**: Resets all UFW rules back to factory defaults.
- **Example**:
  ```bash
  sudo ufw reset
  ```

## Check UFW Status

- **Command**: `sudo ufw status`
- **Description**: Checks the current status of the firewall.
- **Example**:
  ```bash
  sudo ufw status
  ```

## Enable UFW

- **Command**: `sudo ufw enable`
- **Description**: Starts the firewall and updates rules.
- **Example**:
  ```bash
  sudo ufw enable
  ```

## Reload UFW

- **Command**: `sudo ufw reload`
- **Description**: Stops and restarts the UFW.
- **Example**:
  ```bash
  sudo ufw reload
  ```

## Default Deny Incoming Connections

- **Command**: `sudo ufw default deny incoming`
- **Description**: Blocks all incoming connections.
- **Example**:
  ```bash
  sudo ufw default deny incoming
  ```

## Default Allow Outgoing Connections

- **Command**: `sudo ufw default allow outgoing`
- **Description**: Allows all outgoing connections.
- **Example**:
  ```bash
  sudo ufw default allow outgoing
  ```

## Allow Specific Ports

- **Command**: `sudo ufw allow <port>`
- **Description**: Opens specific ports.
- **Example**: Allow SSH (port 22).
  ```bash
  sudo ufw allow 22/tcp
  ```

## Deny Specific Ports

- **Command**: `sudo ufw deny <port>`
- **Description**: Closes specific ports.
- **Example**: Deny Telnet (port 23).
  ```bash
  sudo ufw deny 23/tcp
  ```

## Delete Rules

- **Command**: `sudo ufw delete <rule>`
- **Description**: Deletes rules.
- **Example**: Delete the rule allowing SSH.
  ```bash
  sudo ufw delete allow 22/tcp
  ```

## Disable UFW

- **Command**: `sudo ufw disable`
- **Description**: Shuts down the firewall.
- **Example**:
  ```bash
  sudo ufw disable
  ```

```