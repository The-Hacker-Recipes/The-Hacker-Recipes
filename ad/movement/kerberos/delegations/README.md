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

Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding constrained delegations and rbcd, those types of delegation rely on Kerberos extensions called [Service-for-User](../#service-for-user-extensions) (S4U).

Want to know more about S4U2self and S4U2proxy (required to understand some delegation abuses) : [click here](../#service-for-user-extensions).

Simply put, **Service for User to Self (S4U2self)** allows a service to obtain a Service Ticket, on behalf of another user (called "principal"), to itself. **Service for User to Proxy (S4U2proxy)** allows a service to obtain a Service Ticket, on behalf of a user to a different service.&#x20;

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
From Windows systems, [BloodHound](../../../recon/bloodhound.md) can be used to identify unconstrained and constrained delegation.

The following queries can be used to audit delegations.

```cypher
// Unconstrained Delegation
MATCH (c {unconstraineddelegation:true}) return c

// Constrained Delegation (with Protocol Transition)
MATCH (c) WHERE NOT c.allowedtodelegate IS NULL AND c.trustedtoauth=true return c

// Constrained Delegation (without Protocol Transition)
MATCH (c) WHERE NOT c.allowedtodelegate IS NULL AND c.trustedtoauth=false return c

// Resource-Based Constrained Delegation
MATCH p=(u)-[:AllowedToAct]->(c) RETURN p
```

The Powershell Active Directory module also has a cmdlet that can be used to find delegation for a specific account.

```powershell
Get-ADComputer "Account" -Properties TrustedForDelegation, TrustedToAuthForDelegation,msDS-AllowedToDelegateTo,PrincipalsAllowedToDelegateToAccount
```

<table data-header-hidden><thead><tr><th>Property</th><th>Delegation type</th><th data-hidden></th><th data-hidden></th></tr></thead><tbody><tr><td><code>TrustedForDelegation</code></td><td>Unconstrained Delegation</td><td></td><td></td></tr><tr><td><code>TrustedToAuthForDelegation</code></td><td>Constrained Delegation with Protocol Transition</td><td></td><td></td></tr><tr><td><code>AllowedToDelegateTo</code></td><td>Constrained Delegation, and list of services allowed to delegate to</td><td></td><td></td></tr><tr><td><code>PrincipalsAllowedToDelegateToAccount</code> (i.e. refers to the <code>msDS-AllowedToActOnBehalfOfOtherIdentity</code> attribute)</td><td>RBCD, list of services that can delegate to the account</td><td></td><td></td></tr></tbody></table>
{% endtab %}
{% endtabs %}

### Abuse

{% content-ref url="unconstrained.md" %}
[unconstrained.md](unconstrained.md)
{% endcontent-ref %}

![](../../../../.gitbook/assets/Kerberos\_delegations-unconstrained.drawio.png)

{% content-ref url="constrained.md" %}
[constrained.md](constrained.md)
{% endcontent-ref %}

![](../../../../.gitbook/assets/Kerberos\_delegations-rbcd.png)

{% content-ref url="rbcd.md" %}
[rbcd.md](rbcd.md)
{% endcontent-ref %}

![](../../../../.gitbook/assets/Kerberos\_delegations-rbcd.png)

## Talk :microphone:

{% embed url="https://youtu.be/byykEId3FUs" %}

{% embed url="https://docs.google.com/presentation/d/1rAl-XKrkuFjCpExHBGrp5L8ZwtuFFrOygZMapxMp28I/edit?usp=sharing" %}

{% file src="../../../../.gitbook/assets/Insomnihack 2022 - Delegating Kerberos To Bypass Kerberos Delegation Limitations.pdf" %}

## Resources

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who" %}

{% embed url="https://blog.harmj0y.net/redteaming/another-word-on-delegation/" %}

{% embed url="https://harmj0y.medium.com/s4u2pwnage-36efe1a2777c" %}
