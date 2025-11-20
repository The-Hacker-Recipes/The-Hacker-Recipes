---
authors: BlWasp, ShutdownRepo, felixbillieres
category: ad
---

# SCCM Hierarchy takeover

## Theory

As indicated by [Chris Thompson](https://mobile.twitter.com/_mayyhem) in his article [SCCM Hierarchy Takeover](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087), by default, when a new user is promoted to any SCCM administrative role on a primary site server (for example, `Full Administrator`), the role is automatically propagated to the other SCCM site in the hierarchy by the CAS.

This means that there is no security boundary between SCCM sites in a same hierarchy, and being able to takeover one SCCM site implicates to takeover all the others.

> [!TIP]
> For additional attack techniques and defense strategies related to SCCM hierarchy takeover, refer to the following technique from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [TAKEOVER-4: Relay CAS to Child](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md)

## Practice

There is nothing to do. Just promote a user to any SCCM administrative role on a primary site server (for example, `Full Administrator`), and the role will be automatically propagated to the other SCCM site in the hierarchy by the CAS.

## Resources

[https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087)

[https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md)

