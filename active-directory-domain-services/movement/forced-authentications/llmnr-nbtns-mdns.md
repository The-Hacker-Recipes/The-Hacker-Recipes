---
description: MITRE ATT&CK™ Sub-technique T1557.001
---

# LLMNR, NBT-NS, mDNS spoofing

In some environments \(like Windows ones\), multicast name resolution protocols are enabled by default, such as LLMNR \(Local-Link Multicast Name Resolution\), NBT-NS \(NetBIOS Name Service\) and mDNS \(multicast Domain Name System\). Those environments can fallback to those protocols when standard domain name resolution protocols fail. Windows systems attempt to resolve names in the following order: DNS, LLMNR and NBT-NS.

Attackers can then answer those multicast or broadcast queries. The victims are then redirected to the attacker asking them to authenticate in order to access whatever they ask for. Their authentication is then relayed.

[Responder](https://github.com/SpiderLabs/Responder) \(Python\) and [Inveigh](https://github.com/Kevin-Robertson/Inveigh) \(Powershell\) are great tools for name poisoning. In addition to name poisoning, they also have the ability to start servers \(listeners\) that will [capture authentications](../abusing-lm-and-ntlm/capturing-hashes.md) and echo the NTLMv1/2 hashes to the attacker.

{% tabs %}
{% tab title="Responder" %}
Analyze the network to see if LLMNR, NBT-NS and mDNS are used, and to inspect BROWSER requests.

```bash
responder --interface eth0 --analyze
```

Start LLMNR, NBTS and mDNS poisoning. Fake authentication servers \(HTTP/S, SMB, SQL, FTP, IMAP, POP3, DNS, LDAP, ...\) will capture NTLM hashes.

```bash
responder --interface eth0
```
{% endtab %}

{% tab title="Inveigh" %}
The following command will start poisoning LLMNR, NBT-NS and mDNS and set the Challenge to `1122334455667788` to [crack NTLM hashes](../credentials/cracking.md#practice) with [crack.sh](https://crack.sh/).

```text
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -
```

Flags like ADIDNS, ADIDNSForest, ADIDNSCleanup, ADIDNSThreshold and more can be set to combine LLMNR, NBT-NS and mDNS spoofing with [ADIDNS spoofing](adidns-spoofing.md).
{% endtab %}
{% endtabs %}

## References

{% embed url="http://remivernier.com/index.php/2018/08/26/protocoles-nbt-ns-llmnr-et-exploitation-des-failles/" caption="" %}

{% embed url="https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning" caption="" %}

