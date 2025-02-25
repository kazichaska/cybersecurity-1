# DNS Query and Wireless Security

## DNS

### nslookup

- **nslookup**: A command-line tool used to query DNS records.
- **Example**: Query the SRV records for a domain.
  ```bash
  nslookup -type=srv example.com
  ```

### DNS Record Types

- **A (Address Record)**: Maps a domain name to an IPv4 address.
  - **Example**:
    ```bash
    nslookup -type=a example.com
    ```
- **PTR (Pointer Record)**: Maps an IP address to a domain name (reverse DNS lookup).
  - **Example**:
    ```bash
    nslookup -type=ptr 93.184.216.34
    ```
- **MX (Mail Exchange Record)**: Specifies the mail servers for a domain.
  - **Example**:
    ```bash
    nslookup -type=mx example.com
    ```
- **NS (Name Server Record)**: Specifies the authoritative name servers for a domain.
  - **Example**:
    ```bash
    nslookup -type=ns example.com
    ```
- **SOA (Start of Authority Record)**: Provides information about the domain's DNS zone.
  - **Example**:
    ```bash
    nslookup -type=soa example.com
    ```
- **SRV (Service Record)**: Specifies the location of services for a domain.
  - **Example**:
    ```bash
    nslookup -type=srv _sip._tcp.example.com
    ```
- **TXT (Text Record)**: Contains arbitrary text data, often used for SPF records.
  - **Example**:
    ```bash
    nslookup -type=txt example.com
    ```

## Wireless

### WEP and WPA

- **WEP (Wired Equivalent Privacy)**: An older wireless security protocol that is considered insecure.
- **WPA (Wi-Fi Protected Access)**: A more secure wireless security protocol that replaced WEP.
  - **WPA2**: An improved version of WPA that uses stronger encryption.

### Aircrack-ng

- **Aircrack-ng**: A suite of tools for auditing wireless networks.
- **Example**: Using Aircrack-ng to capture and crack a WPA2 handshake.
  - **Capture Handshake**:
    ```bash
    airodump-ng --bssid <BSSID> --channel <channel> --write <output_file> <interface>
    ```
  - **Crack Handshake**:
    ```bash
    aircrack-ng -w <wordlist> -b <BSSID> <output_file>.cap
    ```

### Wireshark Wireless Analysis and Decryption

- **Wireshark**: A tool for capturing and analyzing network traffic, including wireless traffic.
- **Example**: Using Wireshark to capture and analyze wireless beacon frames.
  - **Filter for Beacon Frames**:
    ```wireshark
    wlan.fc.type_subtype == 0x08
    ```
  - **Capture BSSIDs and SSIDs**: Look at the beacon frame details to find the BSSID (MAC address of the AP) and SSID (network name).
  - **Decrypt Traffic**: Once the wireless key is obtained, use it to decrypt captured traffic and analyze for security risks.

```
