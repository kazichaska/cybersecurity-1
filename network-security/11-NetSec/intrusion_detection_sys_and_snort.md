# Intrusion Detection Systems and Snort

## Role: SOC Analyst for the California DMV

In preparation for the California Consumer Privacy Act (CCPA), we have implemented new security controls using Snort for intrusion detection and prevention at multiple layers of the Defense-in-Depth (DiD) model. This document reviews key concepts and answers specific questions related to IDS, IPS, and Snort configuration.

---

## Questions and Answers

### 1. Differences between a Firewall and an IDS

| Feature       | Firewall                               | IDS (Intrusion Detection System)             |
|---------------|---------------------------------------|---------------------------------------------|
| **Purpose**    | Controls and blocks traffic based on rules | Monitors and alerts on suspicious activity   |
| **Action**     | Preventative (actively blocks threats)   | Detective (does not block, only alerts)     |

---

### 2. Best Placement for IDS: Inline vs. Mirrored Port

- **Best placement:** **Mirrored port (SPAN port)**
- **Why:** This allows passive monitoring without affecting network traffic flow. Inline placement is typically used for IPS rather than IDS.

---

### 3. IDS at the Perimeter Layer of DiD

- **Referred to as:** **Network Intrusion Prevention System (NIPS)**
- **Why:** It inspects incoming and outgoing traffic at the network perimeter to detect and respond to threats.

---

### 4. Snort Alert Breakdown

**Example Snort rule:**
```snort
alert ip any any -> any any {msg: "IP Packet Detected";}
```

| Component    | Explanation                       |
|--------------|-----------------------------------|
| **alert**    | Action to take when rule matches (generate an alert) |
| **ip**       | Protocol to monitor (IP traffic)  |
| **any any**  | Source IP and port (any IP, any port) |
| **->**       | Traffic direction (source to destination) |
| **any any**  | Destination IP and port (any IP, any port) |
| **{msg:...}** | Message displayed when rule triggers |

---

### 5. Intrusion System That Blocks Traffic

- **Intrusion Prevention System (IPS):** Acts on alerts by blocking or preventing malicious traffic.

---

### 6. Two Types of IDS Detection Techniques

1. **Signature-based detection:** Matches traffic against known attack patterns.
2. **Anomaly-based detection:** Identifies deviations from established baselines of normal behavior.

---

### 7. IDS Using Baseline Rules

- **Anomaly-based IDS**: Establishes its rules by learning normal network behavior and flagging anything that deviates.

---

### 8. Signature-Based IDS and Zero-Day Attacks

- **True:** Signature-based IDS cannot detect zero-day attacks since it only recognizes known patterns.

---

### 9. Placement of Firewall, IDS, and IPS

- **Farthest from data:** **Firewall** (placed at the perimeter for first-line defense)
- **IDS** sits behind the firewall for monitoring
- **IPS** can be inline, typically closer to critical data or internal network layers

---

## Bonus Questions

### 1. Snort Rule Header

**Rule header:**
```snort
alert ip any any -> any any
```
- Defines the action, protocol, and source/destination IPs and ports.

---

### 2. Snort Configuration Modes

1. **Sniffer mode:** Captures and displays live packet data.
2. **Packet logger mode:** Logs packets to disk for later analysis.
3. **NIDS mode:** Analyzes network traffic and generates alerts.

---

### 3. IDS vs. IPS

| Feature       | IDS                                 | IPS                               |
|---------------|------------------------------------|----------------------------------|
| **Action**     | Monitors and alerts                 | Blocks and prevents threats       |
| **Placement**  | Passive (mirrored port)            | Inline (actively processes traffic) |

---

### 4. IOA vs. IOC

- **False:** An **Indicator of Attack (IOA)** occurs in real time to detect attack behaviors.
- An **Indicator of Compromise (IOC)** signals evidence of a past breach.

---

### 5. IOA vs. IOC: Proactive vs. Reactive

- **True:**
  - **IOA** = **Proactive** (prevents attacks by detecting malicious activity early)
  - **IOC** = **Reactive** (detects breaches after they happen)

---

### 6. IPS Inline with Traffic

- **True:** IPS is physically connected inline, processes entire subnets of data, and requires robust hardware to handle real-time packet analysis.

---

This document outlines key concepts of intrusion detection and Snort configurations relevant to our role as SOC analysts for the California DMV.
