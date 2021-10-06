# \(KCD\) Constrained

## Theory

If a service account, configured with constrained delegation to another service, is compromised, an attacker can impersonate any user \(e.g. domain admin, except users protected against delegation\) in the environment to access the second service.

Once the final "impersonating" ticket is obtained, it can be used with [Pass-the-Ticket](../pass-the-ticket.md) to access the target service.

## Practice

### Without protocol transition

If the service is configured with constrained delegation **without protocol transition \(which is the case by default\)**, then it works similarly to [unconstrained delegation](unconstrained.md). The attacker controlled service needs to receive a user's ST in order to use the embedded TGT as an identity proof. "Without protocol transition" means the Kerberos authentication protocol needs to be used all the way.

![](../../../../.gitbook/assets/kcd-without-proto-transition.png)

Accounts configured with constrained delegation without protocol transition should be exploited just like [unconstrained delegations](unconstrained.md). The only difference being the final step. When passing the ticket, attackers can impersonate users on a set of specific services.

{% hint style="warning" %}
Attempting to exploit this technique like [Constrained Delegation with protocol transition](constrained.md#with-protocol-transition), getST will raise the following error. However, that error could also/instead mean that the user requested for delegation was protected against it.

```text
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user user1 or initial TGT not forwardable
```
{% endhint %}

### With protocol transition

If the service is configured with constrained delegation **with protocol transition** then it doesn't need that user's ST. It can obtain it with a S4U2Self request and then use it with a S4U2Proxy request. The identity proof can either be a password, an NT hash or an AES key. This process is similar to [resource-based contrained delegation](rbcd.md) exploitation.

![](../../../../.gitbook/assets/kcd-with-protocol-transition.png)

Accounts configured with constrained delegation with protocol transition should be exploited just like [resource-based constrained delegations](rbcd.md). The main difference being the initial step: the attacker doesn't need to edit a target's attribute. Exploitation is limited to what services the delegation can be conducted.

## Resources

{% embed url="https://blog.stealthbits.com/constrained-delegation-abuse-abusing-constrained-delegation-to-achieve-elevated-access/" %}

{% embed url="https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/" %}

