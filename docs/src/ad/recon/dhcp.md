---
authors: ShutdownRepo
category: ad
---

# DHCP

When connecting a computer to most enterprise networks, if the Dynamic Host Configuration Protocol (DHCP) is enabled, it will assign an IP address to that computer, and send a lot of information. Nameservers and domain names are usually set through DHCP offer packets.

On UNIX-like systems, the `/etc/resolv.conf` file will store information for name resolution operations after the DHCP offer.

The [nmap](https://nmap.org/) tool can be used with its [broadcast-dhcp-discover.nse](https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html) script to easily parse those packets.

```bash
nmap --script broadcast-dhcp-discover
```

> [!TIP]
> In many cases, there will be MAC address filtering, static IP addressing, VLANs or other [NAC (Network Access Control) and 802.1x](../../physical/networking/network-access-control.md) that can prevent testers from obtaining this information. In those situations, [Wireshark](https://www.wireshark.org/) can be used to manually inspect broadcast and multicast packets that travel on the network and find valuable information that could help bypass those mitigations.