# Delegations

## Theory

Kerberos delegations allow services to access other services on behalf of domain users.

### Types of delegation

The "Kerberos" authentication protocol features delegation capabilities described as follows. There are three types of Kerberos delegations

* **Unconstrained delegations (KUD)**: a service can impersonate users on any other service.
* **Constrained delegations (KCD)**: a service can impersonate users on a set of services
* **Resource based constrained delegations (RBCD)** : a set of services can impersonate users on a service

{% hint style="info" %}
With constrained and unconstrained delegations, the delegation attributes are set on the impersonating service (requires `SeEnableDelegationPrivilege` in the domain) whereas with RBCD, these attributes are set on the target service account itself (requires lower privileges).
{% endhint %}

### Extensions

Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding constrained delegations and rbcd, those types of delegation rely on Kerberos extensions called S4U2Self and S4U2Proxy.

* **Service for User to Self (S4U2self)**: allows a service to obtain a Service Ticket, on behalf of a user (called "principal"), to itself. This extension can be used by any account that has at least one SPN. The resulting Service Ticket is forwardable (i.e. can be used with S4U2Proxy to access another service) if and only if:
  * the service is configured for **constrained delegation (KCD)** **with protocol transition**
  * the principal is **not "sensitive for delegation"**
  * the principal is **not a member of the Protected Users** group
*   **Service for User to Proxy (S4U2proxy)**: allows a service to obtain a Service Ticket, on behalf of a user to a different service. For this extension to work properly, the service needs to supply a Service Ticket as "additional-ticket" (i.e. used as an evidence that the service using S4U2Proxy has the authority to do it on behalf of a user). For S4U2Proxy to work, the ST used as "additional-ticket" must either be:

    * a **forwardable** ticket
    * or a ticket with it's `PA-PAC-OPTIONS` padata type having the resource-based constrained delegation bit set (n.b. this only applies if the **resource-based constrained delegation (RBCD)** is actually possible and authorized in the proper AD objects attributes).

    S4U2Proxy always results in a forwardable ST, even when the ticket used as evidence wasn't forwardable.

Some of the following parts allow to obtain modified or crafted Kerberos tickets. Once obtained, these tickets can be used with [Pass-the-Ticket](../ptt.md).

## Practice

### Recon

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [findDelegation](https://github.com/SecureAuthCorp/impacket/blob/master/examples/findDelegation.py) (Python) script can be used to find unconstrained, constrained (with or without protocol transition) and rbcd.

```bash
findDelegation.py "DOMAIN"/"USER":"PASSWORD"
```

At the time of writing (13th October 2021), [a Pull Request](https://github.com/SecureAuthCorp/impacket/pull/1184) is pending to feature a `-user` filter to list delegations for a specific account.

```bash
findDelegation.py -user "account" "DOMAIN"/"USER":"PASSWORD"
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [BloodHound](../../../recon/bloodhound.md) can be used to identify unconstrained and constrained delegation but at the time of writing (13th October 2021) RBCD and the state of Protocol Transition (for constrained delegation) are not identified.

The Powershell Active Directory module also has a cmdlet that can be used to find delegation for a specific account.

```powershell
Get-ADComputer "Account" -Properties TrustedForDelegation, TrustedToAuthForDelegation,msDS-AllowedToDelegateTo,PrincipalsAllowedToDelegateToAccount
```

| `TrustedForDelegation`                 | Unconstrained Delegation                                            |   |   |
| -------------------------------------- | ------------------------------------------------------------------- | - | - |
| `TrustedToAuthForDelegation`           | Constrained Delegation with Protocol Transition                     |   |   |
| `AllowedToDelegateTo`                  | Constrained Delegation, and list of services allowed to delegate to |   |   |
| `PrincipalsAllowedToDelegateToAccount` | RBCD, list of services that can delegate to the account             |   |   |
{% endtab %}
{% endtabs %}

### Abuse

{% content-ref url="unconstrained.md" %}
[unconstrained.md](unconstrained.md)
{% endcontent-ref %}

![](../../../../.gitbook/assets/Kerberos\_delegations-unconstrained.png)

{% content-ref url="constrained.md" %}
[constrained.md](constrained.md)
{% endcontent-ref %}

![](../../../../.gitbook/assets/Kerberos\_delegations-constrained.png)

{% content-ref url="rbcd.md" %}
[rbcd.md](rbcd.md)
{% endcontent-ref %}

![](../../../../.gitbook/assets/Kerberos\_delegations-rbcd.png)

## Resources

{% embed url="https://www.harmj0y.net/blog/redteaming/another-word-on-delegation" %}

{% embed url="https://www.harmj0y.net/blog/activedirectory/s4u2pwnage" %}

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who" %}
