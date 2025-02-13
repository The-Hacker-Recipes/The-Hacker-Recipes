---
authors: ShutdownRepo
category: ad
---

# MITM and coerced auths

In Active Directory domains, attackers often rely on coerced authentications and MitM (man in the middle) techniques to operate lateral movement, especially when attempting authentication relaying attacks (e.g. [NTLM relay](../ntlm/relay.md)) or when [abusing Kerberos delegations](../kerberos/delegations/).

These techniques enable attackers to redirect traffic or redirect/force targets authentications. Attackers will then be able, in certain cases, to capture credentials or relay authentications. I'm using "coerce" instead of "force" in this category's title since some technique can rely on a bit of social engineering to work.

There are many ways attackers can do MitM or redirect/force targets authentications, most of which can be combined for maximum impact (and minimum stealth).

> [!WARNING]
> This page is a work-in-progress

| MITM Technique | [ADIDNS](adidns-spoofing.md) | [LLMNR](llmnr-nbtns-mdns-spoofing.md) | [NBNS](../../recon/nbt-ns.md) | [DHCPv6](dhcpv6-spoofing.md) | [ARP](arp-poisoning.md) | [DNS](dns-spoofing.md) | [WPAD](wpad-spoofing.md) | [PrinterBug](ms-rprn.md) | [PrivExchange](../exchange-services/privexchange.md) |
| --------------------------------------------------------------------- | -------------------------- | ------------------------------------ | ------------------------------------ | --------------------------- | ------------------------------------------------------------------ | ---------------------- | ------------------------ | ------------------------ | -------------------------------- |
| Can require waiting for replication/syncing | x | | | | | | | | |
| Easy to start and stop attacks | | x | x | takes \~5 minutes to revert | revert time depends on targets arp cache timeout (usually \~60 sec | x | x | x | x |
| Exploitable when default settings are present | x | x | x | x | x | x | x | x | up to 2019 |
| Impacts fully qualified name requests | x | not if wildcard ADIDNS record exists | not if wildcard ADIDNS record exists | x | | x | | | |
| Requires constant network traffic for spoofing | | x | x | x | x | x | x | | |
| Requires domain credentials | x | | | | | | | x | requires emails-capable account |
| Requires editing AD | x | | | | | | | | |
| Requires privileged access to launch attack from a compromised system | | x | | | x | x | | | |
| Targets limited to the same network segment as the attacker | | x | x | x | x | | | x | x |
| Disruption | low | low | low | low to high | low to high | low to high | low to high | none | none |
