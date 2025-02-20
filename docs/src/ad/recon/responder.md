---
authors: ShutdownRepo, sckdev
category: ad
---

# Responder ⚙️

[Responder](https://github.com/lgandx/Responder) (Python) is a great tool for [LLMNR, NBTNS, MDNS poisoning](../movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing.md) and [WPAD spoofing](../movement/mitm-and-coerced-authentications/wpad-spoofing.md) but it can also be used in "analyze" modes.

* BROWSER mode: inspect [Browse Service](http://ubiqx.org/cifs/Browsing.html) messages and map IP addresses with NetBIOS names 
* LANMAN mode: passively map domain controllers, servers and workstations joined to a domain with the Browser protocol (see [Responder 2.0 - Owning Windows Networks part 3 by Trustwave](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/sheepl-20-automating-people-for-red-and-blue-tradecraft/)).
* LLMNR, NBTNS, MDNS modes: inspect broadcast and multicast name resolution requests

The following command will enable the analyze modes and will give interesting information like

* Domain Controller, SQL servers, workstations
* Fully Qualified Domain Name (FQDN)
* Windows versions in used
* The "enabled" or "disabled" state of protocols like LLMNR, NBTNS, MDNS, LANMAN, BROWSER

```bash
responder --interface "eth0" --analyze
responder -I "eth0" -A
```