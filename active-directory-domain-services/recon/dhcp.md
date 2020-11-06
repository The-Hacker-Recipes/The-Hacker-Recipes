# DHCP

When connecting a computer to most entreprise networks, the Dynamic Host Configuration Protocol \(DHCP\) will assign an IP address to that computer, and send many information. Nameservers and domain name are usually set through DHCP offer packets.

The [nmap](https://nmap.org/) tool can be used with its [broadcast-dhcp-discover.nse](https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html) script to easily parse those packets.

```bash
nmap --script broadcast-dhcp-discover
```

On UNIX-like systems, the `/etc/resolv.conf` file will store that information for name resolution operations.

{% hint style="info" %}
In many cases, there will be MAC address filtering, static IP addressing, VLANs or NAC \(Network Access Control\) that can prevent testers from obtaining thos information
{% endhint %}

