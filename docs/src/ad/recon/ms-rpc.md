---
authors: Anh4ckin3, Sud0Ru, ShutdownRepo
category: ad
---

# MS-RPC

## Theory

MS-RPC (Microsoft Remote Procedure Call) is a protocol that allows requesting service from a program on another computer without having to understand the details of that computer's network. An MS-RPC service can be accessed through different transport protocols, among which:

* a network SMB pipe (listening ports are 139 & 445)
* plain TCP or plain UDP (listening port set at the service creation)
* a local SMB pipe

RPC services over an SMB transport, i.e. port 445/TCP, are reachable through "named pipes"' (through the `IPC$` share). There are many interesting named pipes that allow various operations from NULL sessions context, to local administrative context.

* `\pipe\lsarpc`: enumerate privileges, trust relationships, SIDs, policies and more through the LSA (Local Security Authority)
* `\pipe\samr`: enumerate domain users, groups and more through the local SAM database (only works pre Win 10 Anniversary)
* `\pipe\svcctl`: remotely create, start and stop services to execute commands (used by Impacket's [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) and [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py))
* `\pipe\atsvc`: remotely create scheduled tasks to execute commands (used by Impacket's [atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py))
* `\pipe\epmapper`: used by DCOM (Distributed Component Object Model), itself used by WMI (Windows Management Instrumentation), itself abused by attackers for command execution (used by Impacket's [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)). DCOM is also used by MMC (Microsoft Management Console), itslef abused by attackers for command execution (Impacket's [dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py))

## Practice

### Find exposed services

The epmapper (MS-RPC EndPoint Mapper) maps services to ports. It uses port 135/TCP and/or port 593/TCP (for RPC over HTTP). Through epmapper, tools like Impacket's [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) (Python) or rpcdump.exe (C) from [rpctools](https://resources.oreilly.com/examples/9780596510305/tree/master/tools/rpctools) can find exposed RPC services.

```bash
# with rpcdump.py (example with target port 135/TCP)
rpcdump.py -port 135 $TARGET_IP

# with rpcdump.exe (example with target port 593/TCP)
rpcdump.exe -p 593 $TARGET_IP
```

### Null sessions

NULL sessions are unauthenticated SMB sessions that allow attackers to operate RPC calls through SMB named pipes without being authenticated first. This allows for many recon techniques like the enumeration of domain and local information (users, groups, RIDs, SIDs, policies, etc.).

### Recon through interesting named pipes

The Samba utility named [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can be used to operate recon through MS-RPC services behind SMB named pipes. It offers multiple useful commands.

* `lsaquery`: get domain name and SID (Security IDentifier)
* `enumalsgroups builtin`: list local groups, returns RIDs (Relative IDs)
* `queryaliasmem <RID>`: list local group members, returns SIDs
* `lookupsids <SID>`: resolve SID to name
* `lookupnames <NAME>`: resolve name to SID
* `enumdomusers`: list users, equivalent to `net user /domain`
* `enumdomgroups`: list groups equivalent to `net group /domain`
* `queryuser <rid/name>`: obtain info on a user, equivalent to `net user <user> /domain`
* `querygroupmem <rid>`: obtain group members, equivalent to `net group <group> /domain`
* `getdompwinfo`: get password policy

```bash
rpcclient -c "command1,command2" $TARGET_IP
```

### RID Cycling

RID Cycling is a method that allows attackers to enumerate domain objects by bruteforcing or guessing RIDs and SIDs, based on the fact that RIDs are sequential.

The Python script [ridenum](https://github.com/trustedsec/ridenum) can be used to operate that recon technique, with a Null session or with an authenticated one.

> [!SUCCESS]
> The enum4linux tool can be used to easily operate fast recon through MS-RPC, with Null session or not (see [this page](enum4linux.md)).

### IObjectExporter(IOXIDResolver)

DCOM (Distributed Component Object Model) is a group of Microsoft programs in which client program objects can request services on other computers on a network. DCOM is based on the Component Object Model (COM), which provides a set of interfaces for clients and servers to communicate within the same network.

Among these services is IObjectExporter(OXIDResolver GUID=99fcfec4–5260–101b-bbcb-00aa0021347a), which runs on all machines that can support COM+. The DCE-RPC requests allows to invoke the OXIDResolver service and subsequently from this service we can invoke the [ServerAlive2()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c898afd6-b75d-4641-a2cd-b50cb9f5556d) methods. The ServerAlive2 method retrieves information about network interfaces available on a remote machine in a DCOM/COM environment. Specifically, it provides a list of links (bindings) associated with the network interfaces active on the target machine.

To sum up, if the IOXIDResolver service is active and accessible on a windows host, it is possible to find new network endpoints(like IPv6 address) on this last one (via anonymous connection or with credentials). A python script exists to do this task remotly [IOXIDResolver-ng](https://github.com/Anh4ckin3/IOXIDResolver-ng).
```bash
python IOXIDResolver-ng.py -t $TARGET_IP

# OUTPUT EXEMPLE
[*] Anonymous connection on MSRPC
[+] Retriev Network Interfaces for 192.168.5.20...
[+] ServerAlive2 methode find 3 interface(s)
[+] aNetworkAddr addresse : DC01 (Hostname)
[+] aNetworkAddr addresse : 192.168.5.20 (IPv4)
[+] aNetworkAddr addresse : db69:ecdc:d85:1b54:1676:7fa4:f3fe:4249 (IPv6)
```

### Enumerate Doamin users and computers
Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers.
The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. 
The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implments this type of enumeration
```bash 
python3 nauth.py -t target -u users_file.txt -f computers_file.txt
```

## Resources

[https://mucomplex.medium.com/remote-procedure-call-and-active-directory-enumeration-616b234468e5](https://mucomplex.medium.com/remote-procedure-call-and-active-directory-enumeration-616b234468e5)

[https://actes.sstic.org/SSTIC06/Dissection_RPC_Windows/SSTIC06-article-Pouvesle-Dissection_RPC_Windows.pdf](https://actes.sstic.org/SSTIC06/Dissection_RPC_Windows/SSTIC06-article-Pouvesle-Dissection_RPC_Windows.pdf)

[https://medium.com/nets3c/remote-enumeration-of-network-interfaces-without-any-authentication-the-oxid-resolver-896cff530d37](https://medium.com/nets3c/remote-enumeration-of-network-interfaces-without-any-authentication-the-oxid-resolver-896cff530d37)

[https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)

[https://web.archive.org/web/20220625011947/https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/](https://web.archive.org/web/20220625011947/https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/)