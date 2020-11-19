# NBT-NS

Just like DNS, the NTB-NS \(NetBIOS name service\) protocol is used to translate names to IP addresses. By default, it's used as a fallback in AD-DS.

The tool [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) can be used for reverse lookup \(IP addresses to NetBIOS names\)

```bash
nbtscan -r $SUBNET/$MASK
```

{% embed url="https://wiki.wireshark.org/NetBIOS/NBNS" %}



