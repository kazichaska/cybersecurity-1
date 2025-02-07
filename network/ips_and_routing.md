# IPs and Routing

## Explain How DHCP and NAT Assist with the Transmission of Data Between Private and Public Networks

- **DHCP (Dynamic Host Configuration Protocol)**: Automatically assigns IP addresses to devices on a network, ensuring that each device has a unique IP address.
  - **Example**: A DHCP server assigns an IP address to a laptop when it connects to a network.
    ```bash
    ipconfig /renew
    ```
- **NAT (Network Address Translation)**: Translates private IP addresses to a public IP address for devices to communicate with external networks.
  - **Example**: A router uses NAT to allow multiple devices on a private network to access the internet using a single public IP address.

## Analyze Packet Captures to Diagnose Potential DHCP Issues on a Network

- **DHCP Issues**: Common issues include IP address conflicts, DHCP server unavailability, and incorrect DHCP configurations.
- **Example**: Using Wireshark to capture and analyze DHCP packets.
  - **Filter for DHCP Packets**:
    ```wireshark
    bootp
    ```
  - **Diagnose Issues**: Look for DHCP Discover, Offer, Request, and Acknowledge packets to identify where the process may be failing.

## Optimize Routing Schemes by Determining the Shortest or Quickest Paths Between Multiple Servers

- **Routing Optimization**: Use algorithms like Dijkstra's or Bellman-Ford to determine the shortest or quickest paths between servers.
- **Example**: Using a routing protocol like OSPF (Open Shortest Path First) to optimize routing.
  - **OSPF Configuration**:
    ```bash
    router ospf 1
    network 192.168.1.0 0.0.0.255 area 0
    ```

## Use Wireshark to Visualize Wireless Beacon Signals, Capture BSSIDs and SSIDs, and Determine the Type of Wireless Security Being Used by WAPs

- **Wireless Beacon Signals**: Beacons are frames sent by access points to announce their presence.
- **Example**: Using Wireshark to capture and analyze wireless beacon frames.
  - **Filter for Beacon Frames**:
    ```wireshark
    wlan.fc.type_subtype == 0x08
    ```
  - **Capture BSSIDs and SSIDs**: Look at the beacon frame details to find the BSSID (MAC address of the AP) and SSID (network name).
  - **Determine Wireless Security**: Check the beacon frame's tagged parameters to identify the type of security (e.g., WPA2, WEP).

## Use Aircrack-ng to Obtain a Wireless Key and Decrypt Wireless Traffic to Determine Security Risks

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
  - **Decrypt Traffic**: Once the key is obtained, use it to decrypt captured traffic and analyze for security risks.
