```markdown
# HTTP Cookie Management with Cookie-Editor

## Enable the Chrome Extension Cookie-Editor

Cookie-Editor is a Chrome extension that allows you to view, edit, and manage cookies in your browser.

### Steps to Enable Cookie-Editor

1. **Install Cookie-Editor**:
   - Go to the Chrome Web Store and search for "Cookie-Editor".
   - Click "Add to Chrome" to install the extension.

2. **Enable Cookie-Editor**:
   - After installation, the Cookie-Editor icon will appear in the Chrome toolbar.
   - Click on the Cookie-Editor icon to open the extension.

## Create a User on a Webpage and Export Their Cookie to the Clipboard with Cookie-Editor

### Steps

1. **Create a User**:
   - Go to the webpage where you can create a user account.
   - Fill in the required information and submit the form to create a new user.

2. **Export the Cookie**:
   - Click on the Cookie-Editor icon in the Chrome toolbar.
   - Select the cookie associated with the newly created user.
   - Click "Export" to copy the cookie to the clipboard.

### Example

- **Cookie**:
  ```json
  {
    "name": "sessionId",
    "value": "abc123",
    "domain": "www.example.com",
    "path": "/",
    "expires": "2025-10-21T07:28:00.000Z",
    "httpOnly": true,
    "secure": true
  }
  ```

## Create a New User, Which Will Overwrite the Old User's Cookie and Session

### Steps

1. **Create a New User**:
   - Go to the webpage where you can create a user account.
   - Fill in the required information and submit the form to create a new user.

2. **Verify the New Cookie**:
   - Click on the Cookie-Editor icon in the Chrome toolbar.
   - Verify that the cookie associated with the new user has overwritten the old user's cookie.

### Example

- **New Cookie**:
  ```json
  {
    "name": "sessionId",
    "value": "xyz789",
    "domain": "www.example.com",
    "path": "/",
    "expires": "2025-10-21T07:28:00.000Z",
    "httpOnly": true,
    "secure": true
  }
  ```

## Use the Cookie-Editor Extension to Import Back the First User's Session to Show How a Simple Tool Can Be Used to Swap Sessions

### Steps

1. **Import the First User's Cookie**:
   - Click on the Cookie-Editor icon in the Chrome toolbar.
   - Click "Import" and paste the cookie data of the first user.
   - Click "Save" to apply the changes.

2. **Verify the Session Swap**:
   - Refresh the webpage to verify that the session has been swapped back to the first user.

### Example

- **Import Cookie**:
  ```json
  {
    "name": "sessionId",
    "value": "abc123",
    "domain": "www.example.com",
    "path": "/",
    "expires": "2025-10-21T07:28:00.000Z",
    "httpOnly": true,
    "secure": true
  }
  ```

By following these steps, you can use the Cookie-Editor extension to manage cookies, export and import cookie data, and demonstrate how sessions can be swapped using a simple tool.

```