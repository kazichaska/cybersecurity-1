```markdown
# SQL Injection

Replicants recently received an anonymous email stating that several web vulnerabilities have been identified on the company website. Unfortunately, the anonymous email didn't indicate what they were.

You are first tasked with determining whether the Replicants website is vulnerable to SQL injection. This is one of the most dangerous vulnerabilities and could expose confidential information.

You will test a page on the Replicants website that connects to its database, where an employee can confirm their first and last name by looking up their user id.

Before testing for SQL injection directly on the webpage, you will need to design several SQL queries to test directly against the database, which is represented by a website called DB Fiddle.

## Designing SQL Queries to Test for SQL Injection

### Example 1: Basic Query

- **Query**:
  ```sql
  SELECT first_name, last_name FROM employees WHERE user_id = 1;
  ```

### Example 2: Malicious Query to Bypass Authentication

- **Query**:
  ```sql
  SELECT first_name, last_name FROM employees WHERE user_id = 1 OR 1=1;
  ```

### Example 3: Extracting All Data

- **Query**:
  ```sql
  SELECT * FROM employees WHERE user_id = 1 OR 1=1;
  ```

### Example 4: Using UNION to Extract Data from Another Table

- **Query**:
  ```sql
  SELECT first_name, last_name FROM employees WHERE user_id = 1 UNION SELECT username, password FROM users;
  ```

### Example 5: Commenting Out the Rest of the Query

- **Query**:
  ```sql
  SELECT first_name, last_name FROM employees WHERE user_id = 1; --';
  ```

## Using DB Fiddle to Test SQL Queries

DB Fiddle is an online tool that allows you to test SQL queries in a safe environment. You can use it to design and test your SQL queries before using them to create payloads for SQL injection testing.

### Steps to Use DB Fiddle

1. **Create a New Fiddle**:
   - Go to [DB Fiddle](https://www.db-fiddle.com/).
   - Select the database type (e.g., MySQL, PostgreSQL).

2. **Create Tables and Insert Data**:
   - **Example**:
     ```sql
     CREATE TABLE employees (
       user_id INT PRIMARY KEY,
       first_name VARCHAR(50),
       last_name VARCHAR(50)
     );

     INSERT INTO employees (user_id, first_name, last_name) VALUES (1, 'John', 'Doe');
     INSERT INTO employees (user_id, first_name, last_name) VALUES (2, 'Jane', 'Smith');
     ```

3. **Test SQL Queries**:
   - **Example**:
     ```sql
     SELECT first_name, last_name FROM employees WHERE user_id = 1;
     ```

4. **Test Malicious Queries**:
   - **Example**:
     ```sql
     SELECT first_name, last_name FROM employees WHERE user_id = 1 OR 1=1;
     ```

By designing and testing these SQL queries, you can create payloads to test for SQL injection vulnerabilities on the Replicants website. This will help you identify and mitigate potential security risks.

```