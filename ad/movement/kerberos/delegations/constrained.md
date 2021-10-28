# (KCD) Constrained

## Theory

If a service account, configured with constrained delegation to another service, is compromised, an attacker can impersonate any user (e.g. domain admin, except users protected against delegation) in the environment to access another service the initial one can delegate to.

Constrained delegation can be configured with or without protocol transition. Abuse methodology differs for each scenario. The paths differ but the result is the same: a Service Ticket to authenticate on a target service on behalf of a user.

Once the final Service Ticket is obtained, it can be used with [Pass-the-Ticket](../ptt.md) to access the target service.&#x20;

{% hint style="success" %}
On a side note, a technique called [AnySPN or "service class modification"](../ptt.md#modifying-the-spn) can be used concurrently with pass-the-ticket to change the service class the Service Ticket was destined to (e.g. for the `cifs/target.domain.local` SPN, the service class is `cifs`).
{% endhint %}

![](../../../../.gitbook/assets/Kerberos\_delegations-constrained.png)

## Practice

### With protocol transition

![Domain Controller > Active Directory Users and Computers > delegation properties of a user](<../../../../.gitbook/assets/kcd with protocol transition.png>)

If a service is configured with constrained delegation **with protocol transition**, then it can obtain a service ticket on behalf of a user by combining S4U2Self and S4U2Proxy requests, as long as the user is not sensitive for delegation, or a member of the "Protected Users" group. The service ticket can then be used with [pass-the-ticket](../ptt.md). This process is similar to [resource-based contrained delegation](rbcd.md) exploitation.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) script can be used for that purpose.

```bash
getST -spn "cifs/target" -impersonate "administrator" "domain/service:password"
```

{% hint style="warning" %}
When attempting to exploit that technique, if the following error triggers, it means that either

* the account was sensitive for delegation, or a member of the "Protected Users" group.
* or the constrained delegations are configured [without protocol transition](constrained.md#without-protocol-transition)

```
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user user1 or initial TGT not forwardable
```
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
//TODO rubeus
{% endtab %}
{% endtabs %}

### Without protocol transition

![Domain Controller > Active Directory Users and Computers > delegation properties of a user](<../../../../.gitbook/assets/kcd without proto transition.png>)

If a service is configured with constrained delegation **without protocol transition** (i.e. set with "Kerberos only"), then S4U2Self requests won't result in forwardable service tickets, hence failing at providing the requirement for S4U2Proxy to work.

This means the service cannot, by itself, obtain a ticket for a user to itself (i.e. what S4U2Self is used for). There are two known ways attackers can use to bypass this and obtain a forwardable ticket, on behalf of a user, to the requesting service (i.e. what S4U2Self would be used for):

1. &#x20;By operating an RBCD attack on the service.
2. By forcing or waiting for a user to authenticate to the service while a "Kerberos listener" is running.

While the "ticket capture" way would theoretically work, the RBCD approach is preferred since it doesn't require control over the service's SPN's host (needed to start a Kerberos listener). Consequently, only the RBCD approach is described here at the moment.

#### RBCD approach

The service account (called **serviceA**) configured for KCD needs to be configured for RBCD (Resource-Based Constrained Delegations). The service's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute needs to be appended with an account controlled by the attacker. This second account (called **serviceB**) needs to have at least one SPN.

The attacker can then proceed to a full S4U2 attack (S4U2Self + S4U2Proxy, a standard [RBCD attack](rbcd.md) or [KCD with protocol transition](constrained.md#with-protocol-transition)) to obtain a forwardable ST from a user to one of **serviceA**'s SPNs, using **serviceB**'s credentials.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) script can be used for that purpose.

```bash
getST -spn "cifs/serviceA" -impersonate "administrator" "domain/serviceB:password"
```
{% endtab %}

{% tab title="Windows" %}
//TODO rubeus
{% endtab %}
{% endtabs %}

Once the ticket is obtained, it can be used in a S4U2Proxy request, made by **serviceA**, on behalf of the impersonated user, to obtain access to one of the services **serviceA** can delegate to.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) script can be used for that purpose.

```bash
getST -spn "cifs/target" -impersonate "administrator" -additional-ticket "administrator.ccache" "domain/serviceA:password"
```
{% endtab %}

{% tab title="Windows" %}

{% endtab %}
{% endtabs %}

{% hint style="info" %}
Computer accounts have SPNs set at their creation and can edit their own "rbcd attribute" (i.e. `msDS-AllowedToActOnBehalfOfOtherIdentity`). If the account configured with KCD without protocol transition is a computer, controlling another account to operate the RBCD approach is not needed. In this case, **serviceB **= **serviceA**, the computer account can be configured for a "self-rbcd".
{% endhint %}

## Resources

{% embed url="https://blog.stealthbits.com/constrained-delegation-abuse-abusing-constrained-delegation-to-achieve-elevated-access/" %}

{% embed url="https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/" %}

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who" %}
