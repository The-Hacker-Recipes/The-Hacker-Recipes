---
description: MITRE ATT&CK™ Sub-techniques T1558.001 and T1558.002
---

# Forged tickets

Silver, Golden, Diamond and Sapphire tickets are forged or modified Kerberos tickets that can be used with [pass-the-ticket](../ptt.md) to access services in an Active Directory domain.

<details>

<summary>Glossary</summary>

**PAC (Privileged Authentication Certificate)**: a special set of data contained in the ticket (TGT or Service Ticket) that give information about the requesting user (username, groups, UserAccountControl, etc.).&#x20;

**Long-term key**: the long-term key of an account refers to its NT hash (when the RC4 etype is not disabled in the domain) or another Kerberos key (DES, AES128, AES256).

</details>

**Silver ticket**: the long-term key of a service account can be used to forge a Service ticket that can later be used with [Pass-the-ticket](../ptt.md) to access that service. In a Silver Ticket scenario, an attacker will forge a Service Ticket containing a PAC that features arbitrary information about the requesting user, effectively granting lots of access.

{% content-ref url="silver.md" %}
[silver.md](silver.md)
{% endcontent-ref %}

**Golden ticket**: the long-term key of the `krbtgt` account can be used to forge a special TGT (Ticket Granting Ticket) that can later be used with [Pass-the-ticket](../ptt.md) to access any resource within the AD domain. The `krbtgt`'s key is used to encrypt the PAC. In a Golden Ticket scenario, an attacker that has knowledge of the `krbtgt` long-term key, will usually forge a PAC indicating that the user belongs to privileged groups. This PAC will be embedded in a forged TGT. The TGT will be used to request Service Tickets than will then feature the PAC presented in the TGT, hence granting lots of access to the attacker.

{% content-ref url="golden.md" %}
[golden.md](golden.md)
{% endcontent-ref %}

**Diamond ticket**: Golden and Silver tickets can usually be detected by probes that monitor the service ticket requests (`KRB_TGS_REQ`) that have no corresponding TGT requests (`KRB_AS_REQ`). Those types of tickets also feature forged PACs that sometimes fail at mimicking real ones, thus increasing their detection rates. Diamond tickets can be a useful alternative in the way they simply request a normal ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt it again. It requires knowledge of the target service long-term key (can be the `krbtgt` for a TGT, or a target service for a Service Ticket).

{% content-ref url="diamond.md" %}
[diamond.md](diamond.md)
{% endcontent-ref %}

**Sapphire ticket**: Sapphire tickets are similar to Diamond tickets in the way the ticket is not forged, but instead based on a legitimate one obtained after a request. The difference lays in how the PAC is modified. The Diamond ticket approach modifies the legitimate PAC to add some privileged groups (or replace it with a fully-forged one). In the Sapphire ticket approach, the PAC of another powerful user is obtained through an [S4U2self+u2u](../#s4u2self-+-u2u) trick. This PAC then replaces the one featured in the legitimate ticket. The resulting ticket is an assembly of legitimate elements, and follows a standard ticket request, which makes it then most difficult silver/golden ticket variant to detect.

{% content-ref url="sapphire.md" %}
[sapphire.md](sapphire.md)
{% endcontent-ref %}

The **Bronze bit** vulnerability (CVE-2020-17049) introduced the possibility of forwarding service tickets when it shouldn't normally be possible (protected users, unconstrained delegation, constrained delegation configured with protocol transition).

![](../../../../.gitbook/assets/Kerberos\_delegation.png)

## References

{% embed url="https://en.hackndo.com/kerberos" %}
