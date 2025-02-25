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


```bash
#!/bin/bash

# Array of docker images
images=(
    "splunk/splunk:latest"
    "httpd:2.4"
    "cyberxsecurity/dvwa:latest"
    "mysql:5.7"
    "cyberxsecurity/ufw-firewalld:latest"
    "cyberxsecurity/target-machine:latest"
    "cyberxsecurity/scavenger-hunt:latest"
    "cyberxsecurity/beef:latest"
    "trafex/alpine-nginx-php7:latest"
    "cyberxsecurity/mutillidae:latest"
    "cyberxsecurity/bwapp:latest"
    "mariadb:10.5.1"
    "falcosecurity/falco:0.19.0"
    "wordpress:4.6.1-php5.6-apache"
)

# Docker repository
repo="kazichaska"

# Pull, tag, and push images
for image in "${images[@]}"; do
    docker pull "$image"
    image_name=$(echo "$image" | cut -d':' -f1)
    tag=$(echo "$image" | cut -d':' -f2)
    new_image="$repo/$(basename "$image_name"):$tag"
    docker tag "$image" "$new_image"
    docker push "$new_image"
done
```