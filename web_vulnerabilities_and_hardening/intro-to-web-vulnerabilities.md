```markdown
# Introduction to Web Vulnerabilities

## How HTTP Requests and Responses Work to Make a Web Application Function

HTTP (Hypertext Transfer Protocol) is the foundation of data communication on the web. It defines how requests and responses are formatted and transmitted between clients (browsers) and servers.

### Example

- **HTTP Request**:
  ```http
  GET /index.html HTTP/1.1
  Host: www.example.com
  User-Agent: Mozilla/5.0
  Accept: text/html
  ```

- **HTTP Response**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Length: 1234

  <html>
  <head><title>Example</title></head>
  <body><h1>Hello, World!</h1></body>
  </html>
  ```

## How to Maintain a User's Session Using Cookies

Cookies are small pieces of data stored on the client's browser that are sent to the server with each HTTP request. They are used to maintain a user's session and track user activity.

### Example

- **Set a Cookie**:
  ```http
  HTTP/1.1 200 OK
  Set-Cookie: sessionId=abc123; Path=/; HttpOnly
  ```

- **Send a :
Cookie**  ```http
  GET /dashboard HTTP/1.1
  Host: www.example.com
  Cookie: sessionId=abc123
  ```

## The Various Stacks of a Common Web Architecture and How the Components Within These Stacks Work Together

A common web architecture consists of multiple layers, often referred to as the web stack. The typical components include the client-side (frontend), server-side (backend), and database.

### Example

- **Client-Side (Frontend)**: HTML, CSS, JavaScript
  - **HTML**: Defines the structure of the web page.
  - **CSS**: Styles the web page.
  - **JavaScript**: Adds interactivity to the web page.

- **Server-Side (Backend)**: Server, Application Logic
  - **Server**: Handles HTTP requests and responses.
  - **Application Logic**: Processes data and interacts with the database.

- **Database**: Stores and retrieves data
  - **SQL Database**: MySQL, PostgreSQL
  - **NoSQL Database**: MongoDB, Redis

### How They Work Together

1. The client sends an HTTP request to the server.
2. The server processes the request and interacts with the database if needed.
3. The server generates an HTTP response and sends it back to the client.
4. The client renders the response and displays it to the user.

## How the Database Component Works Within a Web Application

The database component stores and retrieves data for the web application. It is responsible for managing data persistence and ensuring data integrity.

### Example

- **User Registration**:
  1. The user submits a registration form.
  2. The server processes the form data and inserts a new record into the database.
  3. The database stores the user's information.

- **User Login**:
  1. The user submits a login form.
  2. The server queries the database to verify the user's credentials.
  3. The database returns the user's information if the credentials are valid.

## How to Write and Run Basic SQL Queries Against a Database

SQL (Structured Query Language) is used to interact with relational databases. Basic SQL queries include SELECT, INSERT, UPDATE, and DELETE.

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

- **Select Data**:
  ```sql
  SELECT * FROM users;
  ```

- **Update Data**:
  ```sql
  UPDATE users SET password = 'newpassword' WHERE username = 'admin';
  ```

- **Delete Data**:
  ```sql
  DELETE FROM users WHERE username = 'admin';
  ```

By understanding these concepts and examples, you can gain a solid foundation in web vulnerabilities and hardening techniques to secure your web applications.

```