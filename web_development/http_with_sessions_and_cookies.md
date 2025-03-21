```markdown
# HTTP with Sessions and Cookies

## Understand HTTP Requests and Responses

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

## Use the curl Command-Line Tool to Make GET and POST Requests and Examine the Responses

`curl` is a command-line tool used to transfer data to and from a server using various protocols, including HTTP.

### Example

- **GET Request**:
  ```bash
  curl -X GET http://www.example.com/index.html
  ```

- **POST Request**:
  ```bash
  curl -X POST http://www.example.com/login -d "username=user&password=pass"
  ```

- **Examine Response Headers**:
  ```bash
  curl -I http://www.example.com/index.html
  ```

## Explain Different Cookie Types (Permanent and Third-Party)

Cookies are small pieces of data stored on the client's browser that are sent to the server with each HTTP request. They are used to maintain a user's session and track user activity.

### Permanent Cookies

Permanent cookies, also known as persistent cookies, are stored on the user's device for a specified period of time. They remain on the device even after the browser is closed.

- **Example**:
  ```http
  Set-Cookie: sessionId=abc123; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/; HttpOnly
  ```

### Third-Party Cookies

Third-party cookies are set by a domain other than the one the user is visiting. They are often used for tracking and advertising purposes.

- **Example**:
  ```http
  Set-Cookie: trackingId=xyz789; Domain=adnetwork.com; Path=/; HttpOnly
  ```

## Manage Cookies Using the Chrome Extension, Cookie-Editor

Cookie-Editor is a Chrome extension that allows you to view, edit, and manage cookies in your browser.

### Steps

1. **Install Cookie-Editor**:
   - Go to the Chrome Web Store and search for "Cookie-Editor".
   - Click "Add to Chrome" to install the extension.

2. **View Cookies**:
   - Click on the Cookie-Editor icon in the Chrome toolbar.
   - View the list of cookies for the current website.

3. **Edit Cookies**:
   - Select a cookie from the list.
   - Edit the cookie's name, value, domain, path, and expiration date.
   - Click "Save" to apply the changes.

4. **Delete Cookies**:
   - Select a cookie from the list.
   - Click "Delete" to remove the cookie.

## Token Authentication

Token authentication is a method of authenticating users by issuing a token that is sent with each request to verify the user's identity.

### Example

- **Generate Token**:
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

- **Send Token with Request**:
  ```http
  GET /protected-resource HTTP/1.1
  Host: www.example.com
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```

## Use Chrome's Developer Tools to Audit HTTP Request and Response Headers

Chrome's Developer Tools provide a comprehensive set of tools for web developers to inspect and debug web applications.

### Steps

1. **Open Developer Tools**:
   - Right-click on the web page and select "Inspect".
   - Alternatively, press `Ctrl+Shift+I` (Windows/Linux) or `Cmd+Option+I` (Mac).

2. **View Network Activity**:
   - Click on the "Network" tab in the Developer Tools panel.
   - Reload the web page to capture network activity.

3. **Inspect HTTP Requests and Responses**:
   - Click on a network request to view its details.
   - In the "Headers" tab, you can view the request headers and response headers.

4. **Audit Headers**:
   - Check for security-related headers such as `Content-Security-Policy`, `Strict-Transport-Security`, and `X-Content-Type-Options`.
   - Verify that cookies are set with the `HttpOnly` and `Secure` flags.

By understanding these concepts and using these tools, you can effectively manage HTTP requests and responses, handle cookies, and audit web application security.

```
