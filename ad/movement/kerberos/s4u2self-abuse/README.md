# 🛠️ S4U2self abuse

## Theory

Kerberos delegations allow services to access other services on behalf of domain users.

The "Kerberos" authentication protocol features delegation capabilities explained [here](../delegations/). Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding [constrained delegations](constrained.md) and [rbcd](rbcd.md), those types of delegation rely on **Kerberos extensions called S4U2Self and S4U2Proxy**.

**Service for User to Self (S4U2self)** allows a service to obtain a Service Ticket, on behalf of a user (called "principal"), to itself. This extension can be used by any account that has at least one SPN. Depending on the service and principal configurations, the resulting Service Ticket may or may not be forwardable but either way, the ticket can be used for authentication.

Last but not least, S4U2self can be used to produce a Service Ticket to oneself on behalf of another domain user, even if that user is "sensitive for delegation" or member of the Protected Users group. Consequently, this allows attackers to do some privilege escalation.

## Practice

In order to obtain local admin rights on the target machine, the attackers needs to conduct two major steps.

### Obtain a TGT

Obtaining a usable TGT for the machine account, either by knowing one of the machine account's Kerberos keys (RC4, AES128, AES256) or by using [the tgtdeleg trick](http://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/) locally from the machine is the first step to conduct the privilege escalation.&#x20;

The "tgtdeleg" trick can be conducted with [Rubeus](https://github.com/GhostPack/Rubeus) (C#) from the machine as follows.

```powershell
.\Rubeus.exe tgtdeleg /nowrap
```

Alternatively, if the machine account credentials are known, the TGT can be obtained as follows.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [getTGT.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) (Python) script can be used for the purpose.

```bash
getTGT.py -dc-ip "domaincontroller" -hashes :"NThash" "domain"/"machine$"
```
{% endtab %}

{% tab title="Windows" %}
From Windows machines, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose

```powershell
//TODO
```
{% endtab %}
{% endtabs %}

### Obtain a Service Ticket

The TGT can then be used along with S4U2self to obtain a Service Ticket impersonating another domain user on the machine.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s getST.py (Python) script can be used for the purpose.&#x20;

```bash
export KRB5CCNAME="machine$.ccache"
getST.py -self -impersonate 'DomainAdmin' -spn 'host/machine.domain.local' -k -no-pass -dc-ip 'domaincontroller' 'domain.local'/'machine$'
```
{% endtab %}

{% tab title="Windows" %}
From Windows machines, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose

```powershell
.\Rubeus.exe s4u /self /nowrap /impersonateuser:"DomainAdmin" /ticket:"base64ticket"
```
{% endtab %}
{% endtabs %}

Once a Service Ticket is received, it can be used with [pass-the-ticket](../ptt.md)/[pass-the-cache](../ptc.md) to obtain access to oneself as the "DomainAdmin" (the user can be changed in the request. Attackers should select a domain user which has local admin rights on the machine).

## Resources

{% embed url="https://exploit.ph/revisiting-delegate-2-thyself.html" %}

{% embed url="https://cyberstoph.org/posts/2021/06/abusing-kerberos-s4u2self-for-local-privilege-escalation" %}
