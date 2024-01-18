# NBT-NS

Just like DNS, the NTB-NS \(NetBIOS name service\) protocol is used to translate names to IP addresses. By default, it's used as a fallback in AD-DS.

The tools [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) and [nmblookup](https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html) can be used for reverse lookup \(IP addresses to NetBIOS names\)

```bash
# Name lookup on a range
nbtscan -r $SUBNET/$MASK

# Find names and workgroup from an IP address
nmblookup -A $IPAdress
```

{% hint style="success" %}
Some NBT-NS recon can be carried out with the enum4linux tool \(see [this page](enum4linux.md)\).
{% endhint %}

{% embed url="https://wiki.wireshark.org/NetBIOS/NBNS" %}



