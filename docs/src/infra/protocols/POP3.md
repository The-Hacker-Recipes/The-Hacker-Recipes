---
authors: ShutdownRepo, 0xbugatti
---

# `110 TCP`
Post Office Protocol version 3 (POP3) is a widely used email retrieval protocol that allows clients to download emails from a mail server to their local machine. It operates over **TCP port 110 (unencrypted)** and **TCP port 995 (SSL/TLS encrypted - POP3S)**.


### Commands

| Command         | Instruction                                                 |
| --------------- | ----------------------------------------------------------- |
| `USER username` | Identifies the user.                                        |
| `PASS password` | Authentication of the user using its password.              |
| `STAT`          | Requests the number of saved emails from the server.        |
| `LIST`          | Requests from the server the number and size of all emails. |
| `CAPA`          | Requests the server to display the server capabilities.     |


### Authentication over Encryption
	openssl s_client -connect 10.129.14.128:pop3s`
### Password spray 
	`hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3 #passwordspray`
### Brute Force
	`hydra -L users.txt -P pass.txt -f 10.10.110.20 pop3 # ps brute force`
