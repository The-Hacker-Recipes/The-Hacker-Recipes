---
authors: ShutdownRepo, Tednoob17
---

# 🛠️ Telnet

## Theory
Telnet (teletype network) is a  network protocol used to gain access to virtual terminal or remote systems . He made bidirectional text-based communication , but it's unsecured.


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


::: tabs

=== Unix-like

```bash
nc -nv $TARGET_IP $TARGET_PORT
telnet $TARGET_IP $TARGET_PORT
nmap -p  $TARGET_PORT -sVC  --script "*telnet* and safe" $TARGET_IP
```


=== Windows

```bash
nc.exe -nv $TARGET_IP $TARGET_PORT
telnet $TARGET_IP $TARGET_PORT
nmap -p  $TARGET_PORT -sVC  --script "telnet-ntlm-info.nse" $TARGET_IP
```
:::

> [!TIP]
> The $TARGET_PORT is optional, but the default port is 23




### Resources 
https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet


