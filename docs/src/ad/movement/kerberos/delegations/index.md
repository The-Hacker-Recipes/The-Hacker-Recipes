---
authors: ShutdownRepo
category: ad
---

# Delegations

## Theory

Kerberos delegations allow services to access other services on behalf of domain users.

### Types of delegation

The "Kerberos" authentication protocol features delegation capabilities described as follows. There are three types of Kerberos delegations

* Unconstrained delegations (KUD): a service can impersonate users on any other service.
* Constrained delegations (KCD): a service can impersonate users on a set of services
* Resource based constrained delegations (RBCD) : a set of services can impersonate users on a service

> [!TIP]
> With constrained and unconstrained delegations, the delegation attributes are set on the impersonating service (requires `SeEnableDelegationPrivilege` in the domain) whereas with RBCD, these attributes are set on the target service account itself (requires lower privileges).

### Extensions

Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding constrained delegations and rbcd, those types of delegation rely on Kerberos extensions called [Service-for-User](../#service-for-user-extensions) (S4U).

Want to know more about S4U2self and S4U2proxy (required to understand some delegation abuses) : [click here](../#service-for-user-extensions).

Simply put, Service for User to Self (S4U2self) allows a service to obtain a Service Ticket, on behalf of another user (called "principal"), to itself. Service for User to Proxy (S4U2proxy) allows a service to obtain a Service Ticket, on behalf of a user to a different service. 

Some of the following parts allow to obtain modified or crafted Kerberos tickets. Once obtained, these tickets can be used with [Pass-the-Ticket](../ptt.md).

## Practice

### Recon

::: tabs

=== UNIX-like

From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [findDelegation](https://github.com/SecureAuthCorp/impacket/blob/master/examples/findDelegation.py) (Python) script can be used to find unconstrained, constrained (with or without protocol transition) and rbcd.

```bash
findDelegation.py "DOMAIN"/"USER":"PASSWORD"
```

At the time of writing (13th October 2021), [a Pull Request](https://github.com/SecureAuthCorp/impacket/pull/1184) is pending to feature a `-user` filter to list delegations for a specific account.

```bash
findDelegation.py -user "account" "DOMAIN"/"USER":"PASSWORD"
```


=== Windows

From Windows systems, [BloodHound](../../../recon/bloodhound/index) can be used to identify unconstrained and constrained delegation.

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



| Property | Delegation type |  |  |
| --- | --- | --- | --- |
| `TrustedForDelegation` | Unconstrained Delegation |  |  |
| `TrustedToAuthForDelegation` | Constrained Delegation with Protocol Transition |  |  |
| `AllowedToDelegateTo` | Constrained Delegation, and list of services allowed to delegate to |  |  |
| `PrincipalsAllowedToDelegateToAccount` (i.e. refers to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute) | RBCD, list of services that can delegate to the account |  |  |



:::


### Abuse

#### Unconstrained delegations (KUD)

> [!TIP]
> Read the [(KUD) Unconstrained](unconstrained.md) article for more insight

![](<assets/KUD mindmap.png>)

#### Constrained delegations (KCD)
> [!TIP]
> Read the [(KCD) Constrained](constrained.md) article for more insight

![](<assets/KCD mindmap.png>)

#### Resource-Based Constrained Delegations (RBCD)

> [!TIP]
> Read the [RBCD](rbcd.md) article for more insight


![](<assets/RBCD mindmap.png>)

## Talk :microphone:

> [!YOUTUBE] https://www.youtube.com/watch?v=byykEId3FUs


[https://docs.google.com/presentation/d/1rAl-XKrkuFjCpExHBGrp5L8ZwtuFFrOygZMapxMp28I/edit?usp=sharing](https://docs.google.com/presentation/d/1rAl-XKrkuFjCpExHBGrp5L8ZwtuFFrOygZMapxMp28I/edit?usp=sharing)

## Resources

[https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who)

[https://blog.harmj0y.net/redteaming/another-word-on-delegation/](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)

[https://harmj0y.medium.com/s4u2pwnage-36efe1a2777c](https://harmj0y.medium.com/s4u2pwnage-36efe1a2777c)