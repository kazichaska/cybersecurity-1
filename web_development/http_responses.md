```markdown
# HTTP Response Status Codes

HTTP response status codes indicate whether a specific HTTP request has been successfully completed. Responses are grouped in five classes:

- 1xx: Informational
- 2xx: Successful
- 3xx: Redirection
- 4xx: Client Errors
- 5xx: Server Errors

## 200 Codes: Successful Responses

### 200 OK

The request has succeeded. The meaning of the success depends on the HTTP method.

- **Example**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Length: 1234

  <html>
  <head><title>Example</title></head>
  <body><h1>Hello, World!</h1></body>
  </html>
  ```

## 300 Codes: Redirects

### 301 Moved Permanently

The URL of the requested resource has been changed permanently. The new URL is given in the response.

- **Example**:
  ```http
  HTTP/1.1 301 Moved Permanently
  Location: http://www.example.com/new-url
  ```

## 400 Codes: Client Errors

### 400 Bad Request

The server could not understand the request due to invalid syntax.

- **Example**:
  ```http
  HTTP/1.1 400 Bad Request
  Content-Type: text/html
  Content-Length: 123

  <html>
  <head><title>400 Bad Request</title></head>
  <body><h1>Bad Request</h1></body>
  </html>
  ```

### 401 Unauthorized

Although the HTTP standard specifies “unauthorized,” semantically this response means “unauthenticated.” That is, the client must authenticate itself to get the requested response.

- **Example**:
  ```http
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Basic realm="Access to the staging site"
  ```

### 403 Forbidden

The client does not have access rights to the content; that is, it is unauthorized, so the server is refusing to give the requested resource. Unlike 401, the client’s identity is known to the server.

- **Example**:
  ```http
  HTTP/1.1 403 Forbidden
  Content-Type: text/html
  Content-Length: 123

  <html>
  <head><title>403 Forbidden</title></head>
  <body><h1>Forbidden</h1></body>
  </html>
  ```

### 404 Not Found

The server cannot find the requested resource. In the browser, this means the URL is not recognized. In an API, this can also mean that the endpoint is valid but the resource itself does not exist. Servers may also send this response instead of 403 to hide the existence of a resource from an unauthorized client. This response code is probably the most famous one due to its frequent occurrence on the web.

- **Example**:
  ```http
  HTTP/1.1 404 Not Found
  Content-Type: text/html
  Content-Length: 123

  <html>
  <head><title>404 Not Found</title></head>
  <body><h1>Not Found</h1></body>
  </html>
  ```

### 429 Too Many Requests

The user has sent too many requests in a given amount of time (“rate limiting”).

- **Example**:
  ```http
  HTTP/1.1 429 Too Many Requests
  Content-Type: text/html
  Content-Length: 123
  Retry-After: 3600

  <html>
  <head><title>429 Too Many Requests</title></head>
  <body><h1>Too Many Requests</h1></body>
  </html>
  ```

## 500 Codes: Server Errors

### 500 Internal Server Error

The server has encountered a situation it doesn’t know how to handle.

- **Example**:
  ```http
  HTTP/1.1 500 Internal Server Error
  Content-Type: text/html
  Content-Length: 123

  <html>
  <head><title>500 Internal Server Error</title></head>
  <body><h1>Internal Server Error</h1></body>
  </html>
  ```

### 502 Bad Gateway

This error response means that the server, while working as a gateway to get a response needed to handle the request, got an invalid response.

- **Example**:
  ```http
  HTTP/1.1 502 Bad Gateway
  Content-Type: text/html
  Content-Length: 123

  <html>
  <head><title>502 Bad Gateway</title></head>
  <body><h1>Bad Gateway</h1></body>
  </html>
  ```

### 503 Service Unavailable

The server is not ready to handle the request. Common causes are a server that is down for maintenance or is overloaded. Note that, together with this response, a user-friendly page explaining the problem should be sent. This response should be used for temporary conditions and the Retry-After: HTTP header should, if possible, contain the estimated time before the recovery of the service. The webmaster must also take care about the caching-related headers that are sent along with this response, as these temporary condition responses should usually not be cached.

- **Example**:
  ```http
  HTTP/1.1 503 Service Unavailable
  Content-Type: text/html
  Content-Length: 123
  Retry-After: 3600

  <html>
  <head><title>503 Service Unavailable</title></head>
  <body><h1>Service Unavailable</h1></body>
  </html>
  ```

By understanding these HTTP response status codes, you can better diagnose and troubleshoot issues with web applications and ensure proper handling of different types of responses.

```