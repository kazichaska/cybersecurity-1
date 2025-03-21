```markdown
# Using AI to Create a Web Application

We will now use GitHub Copilot, an AI application, to craft a web application. This application will not require any microservices or a database, as it will just be a front end.

## Setup

Setting up GitHub Copilot involves a few steps to get everything running.

### Prerequisites

- **GitHub account**: You will need to have a GitHub account. You can sign up for free at [GitHub](https://github.com/).
- **Visual Studio Code**: You will also need to download and install [Visual Studio Code (VS Code)](https://code.visualstudio.com/).

### Install GitHub Copilot Extension

1. **Open VS Code**: Launch Visual Studio Code on your computer.
2. **Extension Marketplace**: Click on Extensions from the View drop-down menu (or press `Ctrl+Shift+X`).
3. **Search for GitHub Copilot**: In the Extensions view, type "GitHub Copilot" in the search bar.
4. **Install the Extension**: Find the GitHub Copilot extension in the search results and click the Install button.
5. **Sign in to GitHub**:
   - **Activate Extension**: After installing, you will see a prompt to sign in to GitHub to activate GitHub Copilot. Click on Sign In.
   - **Authentication**: This will open a browser window where you can authenticate with your GitHub account. Follow the instructions to complete the sign-in process.
   - **Copilot Signup**: You will see a message now pop up to sign up for Copilot. Click Signup for GitHub Copilot and then click Get access to GitHub Copilot.
   - **Allow Public Code**: When prompted, change the option for 'Suggestions matching public code (duplication detection filter)' to 'Allowed'.
   - **Note**: Click Sign-in again in the bottom window if it doesn't automatically sign you in.

## Using GitHub Copilot

We will now use Copilot to develop a front end.

1. **Open a New File**: Go to File > New Text File.
2. **Open Copilot Chat Prompt**: In the text file window, press `Ctrl+I` to open a chat prompt with Copilot. 
   - **Note**: If the prompt doesn't appear or let you enter a prompt, restart VS Code.
3. **Create an HTML Website**: In the prompt, ask it to create an HTML website on a topic of your choice.
4. **Save the File**: Save the file to your machine (make sure it ends in `.html`) and open it in a browser by double-clicking on it.

### Example

- **Prompt**: "Create an HTML website about space exploration."
- **Generated HTML**:
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <title>Space Exploration</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 20px;
      }
      h1 {
        color: #333;
      }
      p {
        font-size: 16px;
      }
    </style>
  </head>
  <body>
    <h1>Welcome to Space Exploration</h1>
    <p>Space exploration is the ongoing discovery and exploration of celestial structures in outer space by means of continuously evolving and growing space technology.</p>
    <p>Humans have been exploring space for decades, and the journey continues with new missions and discoveries.</p>
  </body>
  </html>
  ```

This is a very basic front end of a website that is a standalone file. It doesn't use any SQL databases or backend services. Copilot can't stand up infrastructure that is required for those types of setups, however, it is very useful for making standalone pages or generating code in general.

```
