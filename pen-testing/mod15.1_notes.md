### Google hacking

`site:megacorpone.com intext:"Powered by"`
`site:megacorpone.com intext:"@megacorpone.com"`
`site:megacorpone.com intext:"contact"`
`ext:txt site:megacorpone.com`
* `site:megacorpone.com filetype:sql` (SQL database dumps)
* `site:megacorpone.com filetype:log` (log files)
* `site:megacorpone.com filetype:env` (environment variables)
* `site:megacorpone.com filetype:txt` (plain text files)
* `site:megacorpone.com filetype:xlsx` (Excel files)
* `site:megacorpone.com filetype:docx` (Word documents)
* `site:megacorpone.com filetype:pdf` (PDF documents)
* `site:megacorpone.com filetype:zip` (compressed archives)

```
 | Name  | Email |

 | ------| ----- | 

 | Joe Sheer | joe@megacorpone.com |

 | Tom Hudson |thudson@megacorpone.com |

 | Tanya Rivera |trivera@megacorpone.com |

 | Matt Smith |msmith@megacorpone.com    |

 | Mike Carlow |mcarlow@megacorpone.com |

 | Alan Grofield |agrofield@megacorpone.com |
```
This user id was able to get me in
`username: thudson password:thudson`

Once in was dropped to path with 3 files

1. index.nginx-debian.html
2. password.lst
3. vpn.sh

`download vpn.sh and it shows rest of the user's and their password`



### Certificate Transparency
`https://crt.sh/?q=sans.org`

### Shadon.io
```
What ports are open? - 22 80 443

What version of SSH is the server running? - SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5

What OS is the server? - Debian

What is the version of the web server running? - Apache/2.4.62 (Debian)

Which vulnerabilities may be present on the server? (CVE numbers are fine.)
    - CVE-2013-4365
    - CVE-2011-2688
    - CVE-2007-4723
    - CVE-2020-11023
    - CVE-2020-11022
    - CVE-2019-11358
    - CVE-2015-9251

Where is this server located? - Montréal, Canada
```

### Recon-ng
`modules search`
`modules load recon/domains-hosts/hackertarget`
`recon/domains-hosts/hackertarget`
`marketplace install reporting/html`
```
CREATOR and CUSTOMER parameters need to be set.
Set the parameters as follows:
CREATOR: Pentester
CUSTOMER: MegaCorpOne
```
`/root/.recon-ng/workspaces/default/results.html`