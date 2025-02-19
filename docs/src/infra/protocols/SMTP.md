---
authors: ShutdownRepo, 0xbugatti
---
# 🛠️ SMTP

# ` 25 TCP`

Simple Mail Transfer Protocol (SMTP) is the standard protocol for sending emails over the internet. It operates on port **25 (unencrypted), 465 (SSL/TLS), and 587 (STARTTLS)** and is responsible for relaying messages between email clients and mail servers.
 
- Conf file `/etc/postfix/main.cf`
- SMTP Commands

| **Command**  | **Description**                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client.                                     |
| `HELO`       | The client logs in with its computer name and thus starts the session.                           |
| `MAIL FROM`  | The client names the email sender.                                                               |
| `RCPT TO`    | The client names the email recipient.                                                            |
| `DATA`       | The client initiates the transmission of the email.                                              |
| `RSET`       | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY`       | The client checks if a mailbox is available for message transfer.                                |
| `EXPN`       | The client also checks if a mailbox is available for messaging with this command.                |
| `NOOP`       | The client requests a response from the server to prevent disconnection due to time-out.         |
| `QUIT`       | The client terminates the session.                                                               |


### **User Name Enumeration**

- Manual:
    - `nc IP 25` OR `telnet IP 25` [25 stands for port which is run smtp on it ]
        - `VRFY admin`      
	        `550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table` user ‘admin’ is not found
        - `VRFY root`
            `252 2.0.0 root`      user ‘root ’ is found 
            
- Automotive:
    - [https://github.com/pentestmonkey/smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)
    
	    `smtp-user-enum -M VRFY -U users.txt -t ip  -p 25`
	> [!SUCCESS]TIP: When Dealing with user name enumeration you can use also   
	> RCPT TO user     or    EXPN user    or    USER user
	

### **Open Relay**

Attack Make You can send Any mail from any  user on smtp server of target to any one

Social Engneering Tip if you found it :
Try To send E-mail From Admin@localdomain in this emai You can put malicious File and send it To Some User To Control its machine

**Validation**

```ruby
msf6 > use scanner/smtp/smtp_relay
msf6 auxiliary(scanner/smtp/smtp_relay) > show options

Module options (auxiliary/scanner/smtp/smtp_relay):

   Name      Current Setting     Required  Description
   ----      ---------------     --------  -----------
   EXTENDED  false               yes       Do all the 16 extended checks
   MAILFROM  sender@example.com  yes       FROM address of the e-mail
   MAILTO    target@example.com  yes       TO address of the e-mail
   RHOSTS                        yes       The target host(s) IP 
   RPORT     25                  yes       The  port of SMTP Service On target
   THREADS   1                   yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smtp/smtp_relay) > set rhost 123.123.123.123
msf6 auxiliary(scanner/smtp/smtp_relay) >run

```





### O365


- domain validation
```
python3 o365spray.py --validate --domain msplaintext.xyz

```
- User Enumeration

```
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz

```
- Password Spraying
```
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

```


Also 
[https://github.com/dafthack/MailSniper](https://github.com/dafthack/MailSniper)




