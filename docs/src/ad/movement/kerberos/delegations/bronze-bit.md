---
description: CVE-2020-17049
authors: ShutdownRepo
category: ad
---

# Bronze Bit

## Theory

When abusing Kerberos delegations, S4U extensions usually come into play. One of those extensions is S4U2proxy. [Constrained](constrained.md) and [Resource-Based Constrained](rbcd.md) delegations rely on that extensions. A requirement to be able to use S4U2proxy is to use an additional service ticket as evidence (usually issued by after S4U2self request). That ticket needs to have the `forwardable` flag set. There are a few reasons why that flag wouldn't be set on a ticket

* the "impersonated" user was member of the "Protected Users" group or was configured as "sensitive for delegation"
* the service account configured for [constrained delegation](constrained.md) was configured for [Kerberos only/without protocol transition](constrained.md#without-protocol-transition)

In 2020, the "bronze bit" (CVE-2020-17049) was released, allowing attackers to edit a ticket and set the `forwardable` flag.

## Practice

The [Impacket](https://github.com/SecureAuthCorp/impacket) script [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) can perform all the necessary steps to edit a ticket's flags and obtain a ticket through S4U2proxy to act as another user on a target service (in this case, "Administrator" is impersonated/delegated account but it can be any user in the environment).

The input credentials are those of the compromised service account configured for constrained delegations.

```bash
getST.py -force-forwardable -spn "$Target_SPN" -impersonate "Administrator" -dc-ip "$DC_HOST" -hashes :"$NT_HASH" "$DOMAIN"/"$USER"
```

The SPN (ServicePrincipalName) set will have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations (more info on [adsecurity.org](https://adsecurity.org/?page_id=183)).

## Resources

[https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-overview](https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-overview)