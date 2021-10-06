# \(KCD\) Constrained

## Theory

If a service account, configured with constrained delegation to another service, is compromised, an attacker can impersonate any user \(e.g. domain admin, except users protected against delegation\) in the environment to access the second service.

Once the final "impersonating" ticket is obtained, it can be used with [Pass-the-Ticket](../pass-the-ticket.md) to access the target service.

## Practice

### Without protocol transition

![](../../../../.gitbook/assets/kcd-without-proto-transition.png)

{% hint style="info" %}
In theory, adding the KCD capable service host to its own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute \([RBCD attack](rbcd.md)\) could allow that host to operate `S4U2Self`, hence allowing the constrained delegation configured without protocol transition to be abused just like [with protocol transition](constrained.md#with-protocol-transition). The reason this is happening is because under KCD configured without protocol transition \(i.e. "with Kerberos only"\) it is not possible to obtain a forwadable service ticket through `S4U2Self`.

This needs to be further checked.
{% endhint %}

### With protocol transition

If the service is configured with constrained delegation **with protocol transition** then it doesn't need that user's ST. It can obtain it with a S4U2Self request and then use it with a S4U2Proxy request. The identity proof can either be a password, an NT hash or an AES key. This process is similar to [resource-based contrained delegation](rbcd.md) exploitation.

![](../../../../.gitbook/assets/kcd-with-protocol-transition.png)

Accounts configured with constrained delegation with protocol transition should be exploited just like [resource-based constrained delegations](rbcd.md). The main difference being the initial step: the attacker doesn't need to edit a target's attribute. Exploitation is limited to what services the delegation can be conducted.

{% hint style="warning" %}
When attempting to exploit that technique, if the following error triggers, it means that either

* the account cannot be delegated
* or the constrained delegations are configured [without protocol transition](constrained.md#without-protocol-transition)

```text
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user user1 or initial TGT not forwardable
```
{% endhint %}

## Resources

{% embed url="https://blog.stealthbits.com/constrained-delegation-abuse-abusing-constrained-delegation-to-achieve-elevated-access/" %}

{% embed url="https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/" %}

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html\#when-accounts-collude---trustedtoauthfordelegation-who" %}

