---
authors: ShutdownRepo
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

## Resources

[https://mucomplex.medium.com/remote-procedure-call-and-active-directory-enumeration-616b234468e5](https://mucomplex.medium.com/remote-procedure-call-and-active-directory-enumeration-616b234468e5)

[https://actes.sstic.org/SSTIC06/Dissection_RPC_Windows/SSTIC06-article-Pouvesle-Dissection_RPC_Windows.pdf](https://actes.sstic.org/SSTIC06/Dissection_RPC_Windows/SSTIC06-article-Pouvesle-Dissection_RPC_Windows.pdf)

