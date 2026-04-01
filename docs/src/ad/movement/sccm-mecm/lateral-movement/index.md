---
authors: BlWasp, ShutdownRepo, felixbillieres
category: ad
---

# Lateral movement

## Theory

Since the main goal of SCCM is to deploy applications and services on the managed assets of the Active Directory, it is also a pretty good candidate to move latteraly on the network. With administrative rights on the primary site server, this can be done by deploying applications and scripts on the targets or coercing clients' authentication.

Additionally, SCCM permits to enumerate many data on the ressources. Among all the services offered by SCCM to the administrator, there is one named CMPivot. This service, located on the MP server, can enumerate all the resources of a computer or computer collection (installed software, local administrators, hardware specification, etc.), and perform administrative tasks on them. It uses a HTTP REST API, named AdminService, provided by the SMS Provider server.

Finally, as indicated by [Chris Thompson](https://mobile.twitter.com/_mayyhem) in his article [SCCM Hierarchy Takeover](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087), by default, when a new user is promoted to any SCCM administrative role on a primary site server (for example, `Full Administrator`), the role is automatically propagated to the other SCCM site in the hierarchy by the CAS.

This means that there is no security boundary between SCCM sites in a same hierarchy, and being able to takeover one SCCM site implicates to takeover all the others.

## Practice

### Admin & Special Account Enumeration

Administrative privileges over the SCCM Management Point (MP) are required to query the MP's WMI database for admin and special accounts.

> [!TIP]
> Read the [enumeration](enumeration.md) article for detailed information on enumerating admin and special accounts.

### Applications and scripts deployment

With administrative rights on the primary site server, applications and scripts can be deployed on target devices to move laterally across the network.

> [!TIP]
> Read the [deployment](deployment.md) article for detailed information on deploying applications and scripts via SCCM.

### AdminService API

The AdminService API can be used to interact directly with SCCM resources for post-exploitation purposes, without using CMPivot.

> [!TIP]
> Read the [AdminService API](adminservice-api.md) article for detailed information on using the AdminService API.

### SCCM Hierarchy takeover

By default, when a new user is promoted to any SCCM administrative role on a primary site server, the role is automatically propagated to the other SCCM site in the hierarchy by the CAS.

> [!TIP]
> Read the [hierarchy takeover](hierarchy-takeover.md) article for detailed information on SCCM hierarchy takeover.

## Resources

[https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/)

[https://enigma0x3.net/2016/02/](https://enigma0x3.net/2016/02/)

[https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/EXEC](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/EXEC)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/RECON](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/RECON)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER)

