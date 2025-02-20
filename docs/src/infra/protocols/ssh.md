---
authors: ShutdownRepo
category: infra
---

# 🛠️ SSH

## Theory

The SSH protocol (Secure Shell) is used to login from one machine to another securely. It offers several options for strong authentication, as it protects the connections and communications security and integrity with strong encryption. This connection can be used for terminal access, file transfers, and for tunneling other applications.

## Enumeration

### Authentication type

It is possible to enumerate the allowed authentication types with the following command:

```bash
ssh -v 
OpenSSH_8.1p1, OpenSSL 1.1.1d 10 Sep 2019
...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

### Banner Grabbing

Useful to get basic information about the SSH server such as its type and version.

```bash
nc -vn  22
...
SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
```

### Server's public SSH key

```bash
ssh-keyscan -t rsa  -p 
```

### Weak Cipher Algorithms

Some auditing tools can help to quikly find the target version and which algorithms are available on the server in order to give recommendations to the customer.

::: tabs

=== sslscan

```bash
sslscan :22
```


=== nmap

```bash
nmap -p22 -n -sV --script ssh2-enum-algos 
```


=== ssh-audit

```bash
ssh-audit -p 22 -4 
```

:::


### SSH fuzzing

Fuzzing the SSH service could help to find vulnerabilities. The automated fuzzing is simple but not very targeted so it usually takes a lot of time and could miss some results.\
The custom and the manual approach is more effective but it takes time to familiarize yourself with the target. Here is an example of a custom fuzzing : [Fuzzing the OpenSSH daemon using AFL](https://github.com/ShutdownRepo/Penetration-Testing-Guides/tree/5140c07692d27c9b3162088ed3aeff1bbbf23d23/servers/abusing-services/www.vegardno.net/2017/03/fuzzing-openssh-daemon-using-afl.html).

::: tabs

=== Automated fuzzing

```bash
msfconsole
use auxiliary/fuzzers/ssh/ssh_version_2
set RHOSTS 
run
```

:::


## Attacks

### Weak cryptographic keys

### Authentication bruteforcing

#### User enumeration

```bash
msfconsole
use scanner/ssh/ssh_enumusers
set RHOSTS 
set USER_FILE 
```

#### Password Bruteforcing

::: tabs

=== Hydra

```bash
hydra -l  -s 22 -P   -t 4 ssh
```


=== Metasploit

```bash
msfconsole
use auxiliary/scanner/ssh/ssh_login
set PASS_FILE /usr/share/wordlists/password/rockyou.txt
set RHOSTS 
set STOP_ON_SUCCESS true
set username 
run
```

:::


Some common ssh credentials [here ](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt)and [here](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt).

#### Private key Bruteforcing

## Resources

[https://book.hacktricks.xyz/pentesting/pentesting-ssh](https://book.hacktricks.xyz/pentesting/pentesting-ssh)

[https://community.turgensec.com/ssh-hacking-guide/](https://community.turgensec.com/ssh-hacking-guide/)