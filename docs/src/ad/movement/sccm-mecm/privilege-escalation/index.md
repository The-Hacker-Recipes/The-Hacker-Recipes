---
authors: BlWasp, ShutdownRepo, q-roland, felixbillieres
category: ad
---

# Privilege escalation

## Theory

There are currently three different pathways for privilege escalation in an SCCM environment in order to take control over the infrastructure:

* [Credential harvesting](credential-harvesting.md)
* [Client Push account authentication coercion](client-push-coercion.md)
* [SCCM site takeover](site-takeover.md)

## Practice

### Credential harvesting

An SCCM infrastructure may contain a wide range of cleartext credentials accessible from various levels of privileges. Some credentials can be associated with privileged accounts in the domain. From a privilege escalation perspective, we are interested in secrets retrievable using an SCCM client or a low-privilege account in the domain.

> [!TIP]
> Read the [credential harvesting](credential-harvesting.md) article for detailed information on harvesting secrets from SCCM policies and Distribution Points.

### Client Push account authentication coercion

If SCCM is deployed via Client Push Accounts, it is possible, from a compromised SCCM client, to coerce the Client Push Account into authenticating to an arbitrary remote resource. It is then possible to retrieve NTLM authentication data in order to crack the account's password or relay the data to other services. Client Push Accounts are privileged as they are required to have local administrator rights on workstations on which they deploy the SCCM client.

> [!TIP]
> Read the [client push coercion](client-push-coercion.md) article for detailed information on coercing Client Push account authentication.

### SCCM site takeover

Some SCCM configurations make it possible to abuse the permissions of the site server / passive site server machine accounts in order to compromise the SCCM infrastructure via relay attacks.

> [!TIP]
> Read the [site takeover](site-takeover.md) article for detailed information on SCCM site takeover techniques.

## Resources

[https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/)

[https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial)

[https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/CRED](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/CRED)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/ELEVATE](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/ELEVATE)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER)

