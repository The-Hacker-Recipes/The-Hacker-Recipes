---
authors: ShutdownRepo, Tednoob17
---

# 🛠️ Telnet

## Theory
Telnet (teletype network) is a  network protocol used to gain access to virtual terminal in local or in remote systems . He provide  bidirectional text-based communication .

----
### Common Telnet Commands

| Command   | Description                                                    |
| --------- | -------------------------------------------------------------- |
| `open`    | Connects to a specified local/remote host                      |
| `close`   | Closes the current connection                                  |
| `quit`    | Exits telnet                                                   |
| `status`  | Shows the current status of the telnet client                  |
| `z`       | Suspends telnet (on Unix/Linux systems)                        |
| `set`     | Sets Telnet options (like terminal type)                       |
| `unset`   | Unsets Telnet options                                          |
| `display` | Displays current settings of Telnet options                    |
| `send`    | Sends special characters or sequences (like break)             |
| `mode`    | Sets the mode of operation (e.g., line by line or character)   |
| `logout`  | Logs out from the remote system (not available on all systems) |


## Enumeration
#### Banner Grabbing
To initiate a connection with telnet server and get any information about the target .


> [!TIP]
> The $TARGET_PORT is optional, but the default port is 23


##### CLI tool
::: tabs

=== Unix-like

```bash
nc -nv $TARGET_IP $TARGET_PORT
telnet $TARGET_IP $TARGET_PORT
shodan stream --ports 23,1023,2323 --datadir telnet-data/ --limit 10000
nmap -p  $TARGET_PORT -sVC  --script "*telnet* and safe" $TARGET_IP
```


=== Windows

```cmd
nc.exe -nv $TARGET_IP $TARGET_PORT
telnet $TARGET_IP $TARGET_PORT
nmap -p  $TARGET_PORT   --script telnet-ntlm-info.nse $TARGET_IP
```
:::

##### Automated tools
::: tabs

=== Metasploit 

```msfconsole
msf > use auxiliary/scanner/telnet/telnet_version
msf > set rhosts $TARGET_IP 
msf > set rport $TARGET_PORT
msf > set threads 5
msf > exploit
```
:::


## Attacks 

#### Brute Force

::: tabs

=== Nmap

```bash
nmap -p 23 --script telnet-brute $TARGET_IP
```

=== Hydra

```bash
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S $TARGET_PORT] telnet://$TARGET_IP 

hydra -l root -P $PATH_TO/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt $TARGET_IP telnet
```

::: 


### Resources 
https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet
https://secybr.com/posts/telnet-pentesting-best-practices/
https://github.com/InfoSecWarrior/Offensive-Pentesting-Host/blob/main/Telnet/README.md

