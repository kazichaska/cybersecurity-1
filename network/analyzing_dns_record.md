# Activity File: Analyzing DNS Record Types

## Role: Security Analyst at Acme Corp

Acme Corp recently updated the DNS records for several of its sites and needs confirmation that the updates were successful.

Your task is to use `nslookup` to validate the DNS records for each of the domains provided.

## Instructions

### Domains to Analyze:
- **splunk.com**
- **fireeye.com**
- **nmap.org**

For each website, determine the following DNS record information and document the findings.

---

## 1. A Record

For each domain:
- **Command Used:**
  ```bash
  nslookup splunk.com
  nslookup fireeye.com
  nslookup nmap.org
  ```
- **Results Include:**
  - **Name:** (e.g., splunk.com)
  - **IP Address:** (Returned IP address)

## 2. NS Record

- **Command Used:**
  ```bash
  nslookup -type=ns splunk.com
  nslookup -type=ns fireeye.com
  nslookup -type=ns nmap.org
  ```
- **Results Include:**
  - **Nameserver FQDN:** (Fully Qualified Domain Name)
  - **Nameserver IP Address:** (Resolved IP address)

## 3. MX Record

- **Command Used:**
  ```bash
  nslookup -type=mx splunk.com
  nslookup -type=mx fireeye.com
  nslookup -type=mx nmap.org
  ```
- **Results Include:**
  - **MX Record:** (Mail Exchange Record)
  - **Priority:** (Numerical priority value)
  - **Hostname:** (Mail server hostname)

---

## Questions

a. **Did any of the domains have more than one MX record?**  
- **Answer:** (Document which domains have multiple MX records and provide reasoning. Typically, multiple MX records offer redundancy and load balancing.)

b. **For nmap.org, list the mail servers from the highest to lowest priority.**  
- **Answer:** (List based on the priority values retrieved from the MX record query.)

---

## Bonus Task: SPF Record Lookup

- **Command Used:**
  ```bash
  nslookup -type=txt nmap.org
  ```
- **Explanation:**  
  The **SPF (Sender Policy Framework) record** specifies which mail servers are authorized to send emails on behalf of nmap.org. Analyze the TXT record that starts with `v=spf1` and explain its configuration.


## Few more examples

```
nslookup -type=txt microsoft.com
;; Truncated, retrying in TCP mode.
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
microsoft.com	text = "MS=ms79629062"
microsoft.com	text = "fg2t0gov9424p2tdcuo94goe9j"
microsoft.com	text = "t7sebee51jrj7vm932k531hipa"
microsoft.com	text = "d365mktkey=3uc1cf82cpv750lzk70v9bvf2"
microsoft.com	text = "d365mktkey=6358r1b7e13hox60tl1uagv14"
microsoft.com	text = "linear-domain-verification=iuq6saifcnbe"
microsoft.com	text = "docusign=d5a3737c-c23c-4bd0-9095-d2ff621f2840"
microsoft.com	text = "d365mktkey=3l6dste9txazu0Qd2zu4135PUB4E35txLxyzJxjkPbsx"
microsoft.com	text = "d365mktkey=JlXV17lfZjyvWxNje1qiP390ACSKzTxo5mGqZ3V2BmYx"
microsoft.com	text = "d365mktkey=QDa792dLCZhvaAOOCe2Hz6WTzmTssOp1snABhxWibhMx"
microsoft.com	text = "d365mktkey=SxDf1EZxLvMwx6eEZUxzjFFgHoapF8DvtWEUjwq7ZTwx"
microsoft.com	text = "d365mktkey=ZGFU0tlXPekPusNHPo5QQQWpVf0gic0xpuKroNy3NQEx"
microsoft.com	text = "d365mktkey=j2qHWq9BHdaa3ZXZH8x64daJZxEWsFa0dxDeilxDoYYx"
microsoft.com	text = "d365mktkey=wbU64GRacxVEQxwcLSQnx0zisXLYzgUbfvsufIqO9ZUx"
microsoft.com	text = "facebook-domain-verification=fwzwhbbzwmg5fzgotc2go51olc3566"
microsoft.com	text = "ms-domain-verification=9feeb5bd-0f21-44bd-aa3d-ad0b1085c629"
microsoft.com	text = "workplace-domain-verification=lK0QDLk73xymCYMKUXNpfKAT8TY5Mx"
microsoft.com	text = "google-site-verification=GfDnTUdATPsK1230J0mXbfsYw-3A9BVMVaKSd4DcKgI"
microsoft.com	text = "google-site-verification=M--CVfn_YwsV-2FGbCp_HFaEj23BmT0cTF4l8hXgpvM"
microsoft.com	text = "google-site-verification=mEAmcTy1e8jIB9W6ENPk2GDg9hjuNytQQRGlK0hPm0c"
microsoft.com	text = "google-site-verification=pjPOauSPcrfXOZS9jnPPa5axowcHGCDAl1_86dCqFpk"
microsoft.com	text = "google-site-verification=uFg3wr5PWsK8lV029RoXXBBUW0_E6qf1WEWVHhetkOY"
microsoft.com	text = "google-site-verification=uhh5_jbxpcQgnb-A7gDIjlrr5Ef34lA2t2_BAveYpnk"
microsoft.com	text = "hubspot-developer-verification=OTQ5NGIwYWEtODNmZi00YWE1LTkyNmQtNDhjMDMxY2JjNDAx"
microsoft.com	text = "atlassian-domain-verification=xvoaqRfxSg3PnlVnR4xCSOlKyw1Aln0MMxRiKXnwWroFG7vI76TUC8xYb03MwMXv"
microsoft.com	text = "v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:spf-a.hotmail.com include:_spf1-meo.microsoft.com -all"

Authoritative answers can be found from:

```

```
nslookup -type=txt google.com
;; Truncated, retrying in TCP mode.
Server:		2601:441:4300:f37:ab4:b1ff:fe39:b72
Address:	2601:441:4300:f37:ab4:b1ff:fe39:b72#53

Non-authoritative answer:
google.com	text = "v=spf1 include:_spf.google.com ~all"
google.com	text = "apple-domain-verification=30afIBcvSuDV2PLX"
google.com	text = "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
google.com	text = "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
google.com	text = "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
google.com	text = "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
google.com	text = "onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef"
google.com	text = "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
google.com	text = "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0"
google.com	text = "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
google.com	text = "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
google.com	text = "cisco-ci-domain-verification=479146de172eb01ddee38b1a455ab9e8bb51542ddd7f1fa298557dfa7b22d963"

Authoritative answers can be found from:
```
---
