# Reconnaissance

When attacking an Active Directory, or in fact any system, it is essential to gather useful information that will help define who, what, when and where. Here are some examples of what information to look for.

* The location of the **domain controllers** (and other major AD services like KDC, DNS and so on). This can be achieved by [resolving standard names](dns.md), by [scanning the network](port-scanning.md) and with [standard LDAP queries](ldap.md)
* The **domain name**. It can be found with [standard LDAP queries](ldap.md), recon through [MS-RPC named pipes](ms-rpc.md), by combining [different recon techniques with enum4linux](enum4linux.md), by [inspecting multicast and broadcast name resolution queries](responder.md), ...
* **Domain objects** and relations between them with [BloodHound](bloodhound.md), with [MS-RPC named pipes](ms-rpc.md) and with [enum4linux](enum4linux.md).
