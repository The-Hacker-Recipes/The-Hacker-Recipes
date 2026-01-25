---
authors: BlWasp, ShutdownRepo, felixbillieres
category: ad
---

# SCCM Hierarchy takeover

## Theory

As indicated by [Chris Thompson](https://mobile.twitter.com/_mayyhem) in his article [SCCM Hierarchy Takeover](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087), by default, when a new user is promoted to any SCCM administrative role on a primary site server (for example, `Full Administrator`), the role is automatically propagated to the other SCCM site in the hierarchy by the CAS.

This means that there is no security boundary between SCCM sites in a same hierarchy, and being able to takeover one SCCM site implicates to takeover all the others.

> [!TIP]
> For additional attack techniques and defense strategies related to SCCM hierarchy takeover, refer to the following techniques from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [TAKEOVER-4: Relay CAS to Child](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md)
> - [TAKEOVER-5: Hierarchy Takeover via NTLM coercion and relay to AdminService on remote SMS Provider](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)

## Practice

### Automatic propagation

There is nothing to do. Just promote a user to any SCCM administrative role on a primary site server (for example, `Full Administrator`), and the role will be automatically propagated to the other SCCM site in the hierarchy by the CAS.

### TAKEOVER-5: NTLM coercion and relay to AdminService

> [!CAUTION]
> This technique only works on Configuration Manager versions prior to 2509. Version 2509 and later reject NTLM authentication at the AdminService. For more details, see [Microsoft's update notes](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/changes/whats-new-in-version-2509#adminservice-now-rejects-ntlm-authentication).

This technique allows an attacker to take over the SCCM hierarchy by relaying coerced NTLM authentication from site servers to remote SMS Providers via the AdminService API. The SMS Provider's AdminService REST API uses Microsoft Negotiate for authentication and, in default configurations prior to version 2509, was vulnerable to NTLM relay attacks.

> [!TIP]
> For detailed requirements, defensive strategies, and practical implementation steps, refer to the [Relay to the HTTP API AdminService](../privilege-escalation/site-takeover.md#relay-to-the-http-api-adminservice) section in the site takeover article, [TAKEOVER-5](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md), and the article "[Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)" by [Garrett Foster](https://twitter.com/garrfoster).

## Resources

[https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087)

[https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md)

[https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)

[https://x.com/_Mayyhem/status/2014005215398101036](https://x.com/_Mayyhem/status/2014005215398101036)
