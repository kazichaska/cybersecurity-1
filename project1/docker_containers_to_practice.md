
Docker container for Cybersecurity - https://hub.docker.com/u/cyberxsecurity

```
sysadmin@ip-10-0-1-155:~$ docker images -a
REPOSITORY                      TAG                   IMAGE ID       CREATED         SIZE
splunk/splunk                   latest                8e9b143bafd6   6 months ago    3.27GB
httpd                           2.4                   19c71fbb7140   7 months ago    148MB
cyberxsecurity/dvwa             latest                53be944b4675   8 months ago    752MB
mysql                           5.7                   5107333e08a8   14 months ago   501MB
cyberxsecurity/ufw-firewalld    latest                91510b4b0fe6   14 months ago   313MB
cyberxsecurity/target-machine   latest                69d174119e65   17 months ago   1.17GB
cyberxsecurity/scavenger-hunt   latest                38cdfeadff47   17 months ago   1.17GB
cyberxsecurity/beef             latest                5e32d543c063   2 years ago     519MB
trafex/alpine-nginx-php7        latest                d03c5e607375   3 years ago     127MB
cyberxsecurity/mutillidae       latest                2174364ff8d1   4 years ago     662MB
cyberxsecurity/bwapp            latest                4d798fe34499   4 years ago     502MB
mariadb                         10.5.1                3c1e634b5a42   4 years ago     358MB
falcosecurity/falco             0.19.0                2029d7d0327e   5 years ago     747MB
wordpress                       4.6.1-php5.6-apache   ee397259d4e5   8 years ago     420MB
```


To start and access the lab, from Canvas select the weblab.

Open your terminal, and run the following 3 commands:

1. **To download the container:**
    ```sh
    sudo docker pull cyberxsecurity/container_project1_v4:latest
    ```

2. **To start the container:**
    ```sh
    sudo docker run -d --hostname=Baker_Street_Linux_Server --network=host --name project1_v4 cyberxsecurity/container_project1_v4:latest
    ```

3. **To connect to the container:**
    ```sh
    sudo docker exec -it project1_v4 /bin/bash
    ```

This will install, configure, and connect you to your lab. Note that this process may take between 5 - 10 minutes to complete!

See below for a screenshot of a successful installation and login.

---

### Example: Using Cybersecurity Docker Containers

Docker containers can be extremely useful for setting up isolated environments for cybersecurity practices. Here is an example of how to use a different cybersecurity-related Docker container:

1. **Download the Metasploit container:**
    ```sh
    sudo docker pull metasploitframework/metasploit-framework
    ```

2. **Start the Metasploit container:**
    ```sh
    sudo docker run -d --name metasploit -p 4444:4444 -p 8080:8080 metasploitframework/metasploit-framework
    ```

3. **Connect to the Metasploit container:**
    ```sh
    sudo docker exec -it metasploit /bin/bash
    ```

4. **Start Metasploit:**
    ```sh
    msfconsole
    ```

This setup allows you to use Metasploit for penetration testing within a controlled environment.

---

Note: If you exit the lab, to return to the lab, run command number 3 from above to reconnect:

```sh
sudo docker exec -it project1_v4 /bin/bash
```
