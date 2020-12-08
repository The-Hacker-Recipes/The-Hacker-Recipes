# Responder

[Responder](https://github.com/SpiderLabs/Responder) \(Python\) is a great tool for [LLMNR, NBTNS, MDNS poisoning](../movement/forced-authentications/llmnr-nbtns-mdns.md) and [WPAD spoofing](../movement/forced-authentications/wpad-spoofing.md) but it can also be used in "analyze" modes.

* **BROWSER mode**: inspect [Browse Service](http://ubiqx.org/cifs/Browsing.html) messages and map IP addresses with NetBIOS names 
* **LANMAN mode**: passively map domain controllers, servers and workstations joined to a domain with the Browser protocol \(see [this](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/responder-20-owning-windows-networks-part-3/)\).
* **LLMNR, NBTNS, MDNS modes**: inspect broadcast and multicast name resolution requests

The following command will enable the analyze modes and will give interesting information like

* Domain Controller, SQL servers, workstations
* Fully Qualified Domain Name \(FQDN\)
* Windows versions in used
* The "enabled" or "disabled" state of protocols like LLMNR, NBTNS, MDNS, LANMAN, BROWSER

```bash
responder --interface eth0 --analyze
```

{% embed url="https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/responder-20-owning-windows-networks-part-3/" %}

