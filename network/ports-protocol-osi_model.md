# Ports, Protocols, and OSI Model

## Interpret Data in Network Packets by Analyzing Their Headers, Payloads, and Trailers

- **Headers**: Contain metadata about the packet, such as source and destination addresses, protocol information, and packet sequencing.
- **Payloads**: The actual data being transmitted.
- **Trailers**: Include error-checking information to ensure data integrity.

## Explain the Role of Ports in Specifying a Network Packet's Destination

- **Ports**: Numerical identifiers in the transport layer that specify the destination application or service on a host.
  - Example: HTTP uses port 80, HTTPS uses port 443.

## Associate Common Protocols with Their Assigned Ports

- **HTTP**: Port 80
- **HTTPS**: Port 443
- **FTP**: Ports 20 and 21
- **SSH**: Port 22
- **DNS**: Port 53
- **SMTP**: Port 25
- **IMAP**: Port 143
- **POP3**: Port 110

## Explain How Encapsulation and Decapsulation Allow Different Protocols to Interact with Each Other

- **Encapsulation**: Wrapping data with protocol-specific headers and trailers as it moves down the OSI layers.
- **Decapsulation**: Removing headers and trailers as data moves up the OSI layers.
- **Interaction**: Encapsulation and decapsulation allow data to be transmitted across different network protocols and devices.

## Use the Layers of the OSI Model to Identify Sources of Problems on a Network

- **Physical Layer**: Check cables, connectors, and hardware.
- **Data Link Layer**: Verify MAC addresses and switch configurations.
- **Network Layer**: Ensure correct IP addressing and routing.
- **Transport Layer**: Check port configurations and firewall rules.
- **Session Layer**: Verify session establishment and termination.
- **Presentation Layer**: Ensure data format and encryption.
- **Application Layer**: Check application configurations and services.

## Capture and Analyze Live Network Traffic Using Wireshark

- **Wireshark**: A tool for capturing and analyzing network traffic.
  - **Capture**: Start a capture session to collect live network packets.
  - **Analyze**: Use filters and inspection tools to analyze packet headers, payloads, and trailers.
  - **Example**: Filter by protocol (e.g., `http`, `tcp`) to focus on specific traffic types.
