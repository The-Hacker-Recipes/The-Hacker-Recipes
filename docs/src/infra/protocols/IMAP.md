---
authors: ShutdownRepo, 0xbugatti
---
# `TCP 143`

`Internet Message Access Protocol` (`IMAP`), allows online management of emails directly on the server and supports folder structures. Thus, it is a network protocol for the online management of emails on a remote server. The protocol is client-server-based and allows synchronization of a local email client with the mailbox on the server

### Commands

| `1 LOGIN username password` | User's login.                                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `1 LIST "" *`               | Lists all directories.                                                                                        |
| `1 LSUB "" *`               | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`            | Selects a mailbox so that messages in the mailbox can be accessed.                                            |
| `1 UNSELECT INBOX`          | Exits the selected mailbox.                                                                                   |
| `1 FETCH <ID> all`          | Retrieves data associated with a message in the mailbox.                                                      |



### Authentication over Encryption 
	`openssl s_client -connect 10.129.136.69:imaps`








