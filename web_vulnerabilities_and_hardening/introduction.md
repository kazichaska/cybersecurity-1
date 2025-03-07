```markdown
# Introduction to Web Vulnerabilities and Hardening

## Articulate the Intended and Unintended Functionalities of a Web Application

Web applications are designed to provide specific functionalities to users, such as data entry, retrieval, and processing. However, unintended functionalities can arise due to improper coding practices, leading to security vulnerabilities.

### Example

- **Intended Functionality**: A login form that allows users to authenticate by entering their username and password.
- **Unintended Functionality**: The same login form may be vulnerable to SQL injection if user inputs are not properly sanitized, allowing attackers to bypass authentication.

## Identify and Differentiate Between SQL and XSS Injection Vulnerabilities

### SQL Injection

SQL injection occurs when an attacker manipulates a web application's SQL query by injecting malicious SQL code. This can lead to unauthorized access to the database, data leakage, and data manipulation.

- **Example**:
  - **Vulnerable Query**:
    ```sql
    SELECT * FROM users WHERE username = '$username' AND password = '$password';
    ```
  - **Malicious **Input:
    ```sql
    ' OR '1'='1
    ```
  - **Resulting Query**:
    ```sql
    SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
    ```

### Cross-Site Scripting (XSS)

XSS occurs when an attacker injects malicious scripts into a web application, which are then executed in the user's browser. XSS can be classified into stored and reflected XSS.

- **Stored XSS**: The malicious script is stored on the server and executed whenever the affected page is loaded.
- **Reflected XSS**: The malicious script is reflected off the server and executed immediately in the user's browser.

- **Example**:
  - **Malicious Input**:
    ```html
    <script>alert('XSS');</script>
    ```

## Design Malicious SQL Queries Using DB Fiddle

DB Fiddle is an online tool that allows you to test SQL queries in a safe environment.

### Example

- **Create a Table**:
  ```sql
  CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50)
  );
  ```

- **Insert Data**:
  ```sql
  INSERT INTO users (id, username, password) VALUES (1, 'admin', 'password123');
  ```

- **Test Malicious Query**:
  ```sql
  SELECT * FROM users WHERE username = 'admin' OR '1'='1';
  ```

## Create Payloads from the Malicious SQL Queries to Test for SQL Injection Against a Web Application

### Example

- **Login Form**:
  ```html
  <form action="/login" method="post">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
  ```

- **Malicious Payload**:
  ```sql
  ' OR '1'='1
  ```

- **Testing**:
  - Enter the malicious payload in the username or password field to test for SQL injection.

## Design Malicious Payloads to Test for Stored and Reflected Cross-Site Scripting Vulnerabilities

### Stored XSS

- **Comment Form**:
  ```html
  <form action="/submit_comment" method="post">
    <textarea name="comment" placeholder="Enter your comment"></textarea>
    <button type="submit">Submit</button>
  </form>
  ```

- **Malicious Payload**:
  ```html
  <script>alert('Stored XSS');</script>
  ```

- **Testing**:
  - Submit the malicious payload through the comment form and check if the script is executed when the comment is displayed.

### Reflected XSS

- **Search Form**:
  ```html
  <form action="/search" method="get">
    <input type="text" name="query" placeholder="Search">
    <button type="submit">Search</button>
  </form>
  ```

- **Malicious Payload**:
  ```html
  <script>alert('Reflected XSS');</script>
  ```

- **Testing**:
  - Enter the malicious payload in the search field and check if the script is executed in the search results page.

By understanding and applying these techniques, you can identify and mitigate web vulnerabilities, ensuring the security and integrity of your web applications.

```