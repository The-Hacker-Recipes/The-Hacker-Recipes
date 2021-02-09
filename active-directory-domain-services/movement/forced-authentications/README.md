# Forced authentications

In Active Directory domains, attackers often rely on forced authentications and MITM \(man in the middle\) to operate lateral movement, especially when attempting authentication relaying attacks \(e.g. [NTLM relay](../abusing-lm-and-ntlm/relay.md)\) or when [abusing Kerberos delegations](../abusing-kerberos/delegations.md).

These techniques enable attackers to redirect traffic or redirect/force targets authentications. Attackers will then be able, in certain cases, to capture credentials or relay authentications.

There are many ways attackers can do MITM or redirect/force targets authentications, most of which can be combined for maximum impact \(and minimum stealth\).

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

| MITM Technique | [ADIDNS](adidns-spoofing.md) | [LLMNR](llmnr-nbtns-mdns.md) | [NBNS](../../recon/nbt-ns.md) | [DHCPv6](dhcpv6-dns-poisoning.md) | [ARP](arp-poisoning.md) | [PrinterBug](printer-bug-ms-rprn-abuse.md) | [PrivExchange](privexchange-pushsubscription-abuse.md) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Can require waiting for replication/syncing | x |  |  |  | ? |  |  |
| Easy to start and stop attacks |  | x | x | takes ~5 minutes to revert | ? | x | x |
| Exploitable when default settings are present | x | x | x | x | ? | x | up to 2019 |
| Impacts fully qualified name requests | x | not if wildcard ADIDNS record exists | not if wildcard ADIDNS record exists | x | ? |  |  |
| Requires constant network traffic for spoofing |  | x | x | x | ? |  |  |
| Requires domain credentials | x |  |  |  | ? | x | requires emails-capable account |
| Requires editing AD | x |  |  |  | ? |  |  |
| Requires privileged access to launch attack from a compromised system |  | x |  |  | ? |  |  |
| Targets limited to the same broadcast/multicast domains as the attacker |  | x | x | x | ? | x | x |

