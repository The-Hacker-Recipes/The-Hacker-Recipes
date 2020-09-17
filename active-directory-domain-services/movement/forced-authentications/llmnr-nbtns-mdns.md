---
description: MITRE ATT&CK™ Sub-technique T1557.001
---

# LLMNR, NBTNS, MDNS poisoning

In some environments \(like Windows ones\), multicast name resolution protocols are enabled by default, such as LLMNR \(Local-Link Multicast Name Resolution\), NBT-NS \(NetBIOS Name Service\) and mDNS \(multicast Domain Name System\). Those environments can rely on those protocols when standard domain name resolution protocols fail.

Attackers can then answer those multicast or broadcast queries. The victims are then redirected to the attacker asking them to authenticate in order to access whatever they ask for. Their authentication is then relayed.

[Responder](https://github.com/SpiderLabs/Responder) \(Python\) and [Inveigh](https://github.com/Kevin-Robertson/Inveigh) \(Powershell\) are great tools for name poisoning. In addition to name poisoning, they also have the ability to start servers \(listeners\) that will [capture authentications](../abusing-ntlm/capturing-hashes.md) and echo the NTLMv1/2 hashes to the attacker.

{% tabs %}
{% tab title="Responder" %}
Analyze the network to see if LLMNR, NBT-NS and mDNS are used.

```bash
responder --interface eth0 --analyze
```

Start poisoning, enable answers for netbios wredir and domain suffix queries, and force LM hashing downgrade.

```bash
responder --interface eth0 --wredir --NBTNSdomain --wpad --lm
```
{% endtab %}

{% tab title="Inveigh" %}
Start poisoning LLMNR, NBT-NS and mDNS

```text
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y
```
{% endtab %}
{% endtabs %}

## References

{% embed url="http://remivernier.com/index.php/2018/08/26/protocoles-nbt-ns-llmnr-et-exploitation-des-failles/" caption="" %}

{% embed url="https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning" caption="" %}

