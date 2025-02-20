---
authors: ShutdownRepo, Tednoob17
category: infra
---

# 🛠️ Telnet

## Theory
Telnet (teletype network) is a  network protocol used to gain access to a  virtual terminal in local or in remote systems . It provides  bidirectional text-based communication .

----
### Common telnet commands

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


## Practice
### Enumeration
#### Banner grabbing
To initiate a connection with telnet server and get any information about the target .

> [!TIP]
> The `$TARGET_PORT` is optional, but the default port is 23



::: tabs

=== Unix-like

The Telnet banner of a target can be captured using multiple tools on UNIX-like systems.

```bash
#Using Netcat
nc -nv $TARGET_IP $TARGET_PORT

#Using Telnet
telnet $TARGET_IP $TARGET_PORT

#Using Shodan-cli
shodan stream --ports 23,1023,2323 --datadir telnet-data/ --limit 10000

#Using nmap
nmap -p  $TARGET_PORT -sVC  --script "*telnet* and safe" $TARGET_IP
```
The Metasploit framework can also be used to make this work.

```
msf > use auxiliary/scanner/telnet/telnet_version
msf > set rhosts $TARGET_IP
msf > set rport $TARGET_PORT
msf > set threads 5
msf > exploit
```

=== Windows

On Windows systems, multiple tools can be used to capture the Telnet banner of a target.

```powershell
nc.exe -nv $TARGET_IP $TARGET_PORT

telnet $TARGET_IP $TARGET_PORT

nmap.exe -p  $TARGET_PORT   --script telnet-ntlm-info.nse $TARGET_IP
```
:::




### Attacks

#### Passwordless authentication

Telnet can be configured to allow users to connect to a server without needing a specific identity by utilizing a passwordless login feature. This method is commonly employed for accessing or downloading public files.

To connect without a password, one would use the following command:

```bash
telnet $TARGET_IP

# provide username, without password
```

#### Common credentials

If anonymous login is disabled on the Telnet server, trying common usernames and passwords like admin, administrator, root, user, or test can be a good initial step. This approach is less aggressive than attempting to guess passwords through brute force and is recommended to try first when accessing a server.

```bash
telnet $TARGET_IP

# provide a common username with a common password
```


#### Brute Force

::: tabs

=== Nmap

```bash
nmap -p 23 --script telnet-brute $TARGET_IP
```

=== Metasploit framework


```
use auxiliary/scanner/telnet/telnet_login
msf auxiliary(telnet_login) > set rhosts  $TARGET_IP
msf auxiliary(telnet_login) > set user_file /path/to/user.txt
msf auxiliary(telnet_login) > set pass_file /path/to/pass.txt
msf auxiliary(telnet_login) > set stop_on_success true
msf auxiliary(telnet_login) > exploit
```

=== Hydra

```bash
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S $TARGET_PORT] telnet://$TARGET_IP

hydra -l root -P $PATH_TO/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt $TARGET_IP telnet
```

:::


## Resources
[pentesting-telnet](https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet)
[telnet-pentesting-best-practices](https://secybr.com/posts/telnet-pentesting-best-practices)
[Offensive-Pentesting-Host](https://github.com/InfoSecWarrior/Offensive-Pentesting-Host/blob/main/Telnet/README.md)
[Telnet](https://techyrick.com/pentesting-telnet)