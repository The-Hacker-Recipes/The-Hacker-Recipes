---
description: MITRE ATT&CK™ Sub-technique T1557.001
---

# LLMNR, NBT-NS, mDNS spoofing

In some environments (like Windows ones), multicast name resolution protocols are enabled by default, such as LLMNR (Local-Link Multicast Name Resolution), NBT-NS (NetBIOS Name Service) and mDNS (multicast Domain Name System). Those environments can fallback to those protocols when standard domain name resolution protocols fail. Windows systems attempt to resolve names in the following order: DNS, LLMNR and NBT-NS.

Attackers can then answer those multicast or broadcast queries. The victims are then redirected to the attacker asking them to authenticate in order to access whatever they ask for. Their authentication is then relayed.

[Responder](https://github.com/lgandx/Responder) (Python) and [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (Powershell) are great tools for name poisoning. In addition to name poisoning, they also have the ability to start servers (listeners) that will [capture authentications](../ntlm/capture.md) and echo the NTLM hashes to the attacker. Another possibility would be to start similar listeners, and [relay the NTLM authentications](../ntlm/relay.md) to other resources the attacker wants to access.

{% tabs %}
{% tab title="UNIX-like" %}
The following command will make Responder analyze the network to see if LLMNR, NBT-NS and mDNS are used, and to inspect BROWSER requests.

```bash
responder --interface "eth0" --analyze
responder -I "eth0" -A
```

The following command will start LLMNR, NBTS and mDNS spoofing. Name resolution queries for the wpad server will be answered just like any other query. Fake authentication servers (HTTP/S, SMB, SQL, FTP, IMAP, POP3, DNS, LDAP, ...) will [capture NTLM hashes](../ntlm/capture.md).

```bash
responder --interface "eth0"
responder -I "eth0"
```
{% endtab %}

{% tab title="Windows" %}
The following command will make Inveigh inspect the network to see if LLMNR, NBT-NS and mDNS are used.

```powerquery
Invoke-Inveigh -ConsoleOutput Y -Inspect
```

The following command will start LLMNR, NBTS and mDNS spoofing. Name resolution queries for the wpad server will be answered just like any other query. Fake authentication servers (HTTP/S, SMB, DNS, LDAP, ...) will [capture NTLM hashes](../ntlm/capture.md) (even from machine accounts) and set the Challenge to `1122334455667788` (to [crack NTLM hashes](../credentials/cracking.md#practice) with [crack.sh](https://crack.sh/)).

Inveigh also starts a WPAD rogue proxy server by default for [WPAD abuse](wpad-spoofing.md).

```powershell
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```

Flags like `-ADIDNS,` `-ADIDNSForest,` `-ADIDNSCleanup`, `-ADIDNSThreshold` and more can be set to combine LLMNR, NBT-NS and mDNS spoofing with [ADIDNS spoofing](adidns-spoofing.md).

[This wiki page](https://github.com/Kevin-Robertson/Inveigh/wiki/Basics) can be really useful to help master Inveigh and its support functions

* `Clear-Inveigh` to clear the $inveigh hashtable
* `Get-Inveigh` to get data from the $inveigh hashtable
* `Stop-Inveigh` to stop all running Inveigh modules
* `Watch-Inveigh` to enable real time console output
{% endtab %}
{% endtabs %}

## Resources

{% embed url="http://remivernier.com/index.php/2018/08/26/protocoles-nbt-ns-llmnr-et-exploitation-des-failles/" %}

{% embed url="https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning" %}
