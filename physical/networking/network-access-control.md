---
description: Bypassing Network Access Control Systems
---

# Network Access Control

## Theory

[NAC](https://en.wikipedia.org/wiki/Network\_Access\_Control) (Network Access Control) acts as a kind of a gatekeeper to the local network infrastructure. Its usually works with whitelists, blacklists, authentication requirements or host scanning to restrict access and keep unwanted devices out of the network.

### Basics

NAC is a principle. It can be setup with several measures.

* Filtering of MAC addresses
* Authentication with username & password
* Authentication with certificates
* Fingerprinting
* Host checks

NAC aims at protecting against the including, but not limited to, scenarios.

* Employees bringing rogue devices (willingly or not)
* Service providers acting inside the IT / OT network\*
* Attackers trying to gain access to the internal network

_\*IT/OT network: Information Technology (workstations, users, shares, ...) and_ [_Operational Technology_](https://en.wikipedia.org/wiki/Operational\_technology) _(machines, productionl lines, ...)._

### Infrastructure & auth flow

Most commonly, NAC solution are based on [802.1x](https://en.wikipedia.org/wiki/IEEE\_802.1X) which is a standard for port based network access. It will interact with the switches (most likely and mainly via SNMP) and allow or block ports based on the preset rules. There are 3 actors involved:

* **The supplicant**: the client that is asking for network access
* **The authenticator**: the device that acts as the gatekeeper and to which the clients connects - most likely a switch.
* **The authentication server**: something in the background that validates the requests and grants or denies access to the supplicant.

By default, the ports are in an unauthorized state and will only be allowed to transmit and receive [EAPOL](https://www.vocal.com/secure-communication/eapol-extensible-authentication-protocol-over-lan/) frames (Extensible Authentication Protocol Over LAN), which basically is encapsulated [EAP](https://en.wikipedia.org/wiki/Extensible\_Authentication\_Protocol).

1. These EAPOL frames are forwarded from "the client desiring access to the network" to "the switch".
2. The switch unpacks the EAPOL and forwards the EAP packet to an authentication server, which in most cases will be a **RADIUS** server.

From there everything goes vice versa. As EAP is more a framework than a protocol, it contains several EAP methods for authentication. The most commonly known variants are EAP-TLS, EAP-MD5, EAP-PSK and EAP-IKEv2, allowing to authenticate by preshared keys, passwords, certificates or other mechanisms.

![802.1x auth flow (Wikipedia)](<../../.gitbook/assets/image (6) (1).png>)

When all checks are passed, the port will be switched to authorized and thus be allowed for normal network traffic.

An infrastructure that is capable of talking 802.1x is needed for all this to work properly. The infrastructure is comprised of **supplicants** (i.e. clients), **authenticators** (i.e. switches) and **authentication servers** (i.e. [RADIUS](https://en.wikipedia.org/wiki/RADIUS) servers).

A short overview from Gartner lists and reviews many NAC solutions: [NAC Reviews & Ratings](https://www.gartner.com/reviews/market/network-access-control).

## Offensive tooling (dropbox)

### Hardware

A device, known as "dropbox", is needed to carry out according attacks when conducting NAC penetration tests. The following setup is a commonly used for this type of engagements.

* Raspberry Pi 4 8GB
* SD card
* 3.5” TFT with Case
* Additional USB Ethernet Adapter Power Adapter
* Keyboard
* (optional) Powerbank
* (optional) LTE USB modem

![Raspberry Pi drop box](<../../.gitbook/assets/image (7).png>)

The Raspberry can be flushed with [the official ARM image of Kali](https://www.kali.org/get-kali/#kali-arm).

The integrated wireless interface can be used to spawn a hotspot to be able to connect via SSH.

### Initial setup

The following commands can then be run to install the necessary libraries and tools.

```
sudo apt-get install isc-dhcp-server  
sudo apt-get install hostapd  
sudo systemctl enable isc-dhcp-server  
sudo systemctl unmask hostapd  
sudo systemctl enable hostapd 
```

### DHCP configuration

The DHCP configuration file is located at `/etc/dhcp/dhcpd.conf` and can be edited to determine how the dropbox will act as a DHCP server.

```
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.200.0 netmask 255.255.255.0 {
range 192.168.200.2 192.168.200.20;
option subnet-mask 255.255.255.0;
option broadcast-address 192.168.200.255;
}
```

### Wi-Fi configuration

The host access point daemon (hostapd) configuration file is located at `/etc/hostapd/hostapd.conf` and can be edited to determine how the dropbox will act as a wireless access point.

```
interface=wlan0
driver=nl80211
ssid=kali_hotspot
hw_mode=g
channel=11
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_passphrase=Sup3rS3cr3tW1F1P@ss!
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_group_rekey=86400
ieee80211n=1
wme_enabled=1
```

## Abuse

There are several scenarios to take into consideration with specific bypass possibilities.

Companies usually have devices that don't fully support 802.1x. Among them can be printers, VOIP equipment, cameras, etc. These will usually be granted access to the network only by having their MAC address in a whitelist. This is often dubbed "MAC-based NAC".

MAC-based and 802.1x are usually managed one of many ways:

* by setting up each physical RJ45 port (i.e. the authenticator) in the building to do either MAC-based NAC or 802.1x -> [MAC-based bypass](network-access-control.md#mac-address-used-as-only-authentication-feature)
* by having the authenticator (i.e. port) check if the devices than connect support 802.1x and switch to MAC-based if they don't
* by mixing MAC-based and authentication (i.e. 802.1x): the MAC address is checked and authentication then takes place -> [MAC-based + authentication](network-access-control.md#mac-address-needs-to-be-authorized-and-authentication-required)



{% hint style="info" %}
Devices like the [Basilisk](https://ringtail.ch/products/basilisk-automatic-ethernet-ghosting), [Basilisk Zero](https://ringtail.ch/products/basilisk-zero-automatic-ethernet-ghosting), or [Skunk](https://ringtail.ch/products/skunk-gigabit-ethernet-tap-switch) can be helpful in NAC-bypass engagements. _Nota bene: keep in mind ghosted Linux machines will require custom iptable rules to work smoothly._
{% endhint %}

### MAC-based only <a href="#mac-address-used-as-only-authentication-feature" id="mac-address-used-as-only-authentication-feature"></a>

[MAC Authentication Bypass (MAB)](https://networklessons.com/cisco/ccie-routing-switching-written/mac-authentication-bypass-mab) can be done by spoofing an authorized MAC address.

The first step in spoofing an authorized MAC address is to find one. This can be done by physically searching addresses on printers, labels, IP phones and similar equipment, or by using [Wireshark](https://www.wireshark.org/) to manually inspect broadcast and multicast packets that travel on the network and obtain some MAC addresses in the traffic.c.

[macchanger](https://github.com/alobbs/macchanger) can then be used to spoof the a MAC address. Once there, cables can be swapped to access the customer's network.

```bash
# manually set the address
macchanger -m "AA:BB:CC:DD:EE:FF" eth0

# reset the address to the permanent physical MAC
macchanger -p eth0
```

{% hint style="info" %}
Some errors may be raised when the interface settings cannot be changed. This is usually due to the interface being used.

```bash
ifdown eth0
macchanger -m "AA:BB:CC:DD:EE:FF" eth0
ifup eth0
```
{% endhint %}

### Authentication only <a href="#mac-address-used-as-only-authentication-feature" id="mac-address-used-as-only-authentication-feature"></a>

Same thing as [MAC-based + authentication](network-access-control.md#mac-address-needs-to-be-authorized-and-authentication-required-1), without the MAC-based verification bypass.

A regular authentication to 802.1x (and others) systems can be conducted with [xsupplicant](https://github.com/Zero3K/xsupplicant) (C).

### MAC-based + authentication <a href="#mac-address-needs-to-be-authorized-and-authentication-required" id="mac-address-needs-to-be-authorized-and-authentication-required"></a>

In this case, access to the network is granted if the supplicant's MAC address is whitelisted and if the authentication then succeeds.

Just like with [MAC-based](network-access-control.md#mac-address-used-as-only-authentication-feature) bypass, the first step is to find an authorized MAC address.

The second step is to access the port without authentication, which leaves at least two possible ways, both relying on [the dropbox](network-access-control.md#offensive-tooling-dropbox).

#### Using a Hub

Use a Hub, switch the MAC address to the victim's one, connect the drop box and the victim to the same ethernet port. The “real” device will do the auth stuff, putting the port into authorized mode, and allow both devices to connect to the network. As both have the same MAC, the switch will only have one entry in its ARP / SAT table, not raising suspicion.

{% hint style="info" %}
But there is a downside to this method. As long as stateless protocols like UDP are used, both devices can communicate just fine. However when it comes to using stateful protocols like TCP, they will for certain run into issues, as one device behind the Hub will be the first to receive and drop or answer a package e.g. in the 3-way-handshake. One could unplug the original device after it opened the port and have a fully capable device inside the network, but this might very quickly raise alarms, when the device is somewhat monitored and will block access to the network when the next authentication needs to be done.
{% endhint %}

#### Using a transparent bridge

This idea involves a device that - simply spoken - in a first instance just lets all the traffic traverse it by means of forwarding rules, being totally transparent to the network and all the participants. Tt then does some tcpdump magic to sniff traffic like ARP, NetBIOS but also Kerberos, Active Directory, web etc., extracting the needed info to spoof the victim and the networks gateway to stay under the radar. With this info the needed rules in ebtables, iptables etc. are automatically created, and will allow an attacker to interact with the network mimicking the victim.

There is an awesome tool called [nac\_bypass](https://github.com/scipag/nac\_bypass) from [Mick Schneider](https://twitter.com/0x6d69636b) which he walks through in [this](https://www.scip.ch/?labs.20190207) blog post.

The steps are as follows:

* find a target deivce and put the dropbox in between
* start the `nac_bypass_setup.sh` script

![](<../../.gitbook/assets/image (9) (1).png>)

{% hint style="info" %}
To manually specify the interfaces, one can do so with the <mark style="color:blue;">-1</mark> and <mark style="color:blue;">-2</mark> switches. By default it will treat the lower device as switch side facing, and the next one as victim facing interface.
{% endhint %}

* Wait until the script gathered the MAC address of the attacked system, the IP of the attacked system and the gateway's MAC address in order to perform the attack. If all went well the following info will show up and the device should be able to talk to the network:

![](<../../.gitbook/assets/image (5).png>)

* run other offensive tools for [NTLM capture](../../ad/movement/ntlm/capture.md), [relay](../../ad/movement/ntlm/relay.md), etc.

{% hint style="info" %}
Responder needs to bet set up to listen on the bridge interface, but change the answering IP address to the one of the victim.

```bash
responder --interface br0 --externalip $VICTIM
```
{% endhint %}

## Mitigation <a href="#defense" id="defense"></a>

In general an 802.1x implementation will prevent employees or service providers from connecting rogue devices to the network. To a certain extend it may also block script kiddies that don't have the l33t skillz to bypass it. For more advanced adversaries, the attacks will most likely be successful.

Here are some general guidelines for keeping things as secure as possible:

* Separate devices that authenticate by MAC only
* Reduce the time for re-authentication to minimize the hub attack scenario. Leaving ports open after a successful 802.1x authentication for an hour will pose a much higher risk than 5 minutes.
* Use MACSec if possible. This will at least make it much harder for an attacker to gather the needed info to play for Man in the Middle.
* Monitoring:
  * Uncommon link up/downs on switches
  * Speed / duplex changes
  * Changes in framesizes (e.g. Windows vs Linux)
  * Changed TTLs
  * Access to systems and services that normally don´t get accessed (firewall logs)
  * Monitor network traffic and detect attacks / unknown patterns (IDS/IPS/SIEM)
* Unneeded ports must be disabled/disconnected.
* Don't expose unneeded info. Stickers with IP/MAC addresses will make it much easier for an attacker. Same goes for access to IP phone or printer menus to gather network intel. Restrict them as much as possible.
* Restrict access to the systems. If someone is not able to get in between, he can't carry out attacks.
* Awareness: train employees to ask questions and inform people, when they see a suspicious device hanging from a printer or stuff like that.

## Resources

{% embed url="https://www.youtube.com/watch?v=rurYRDlf1Bo" %}

{% embed url="https://www.gremwell.com/marvin-mitm-tapping-dot1x-links" %}

{% embed url="https://github.com/Orange-Cyberdefense/fenrir-ocd" %}
802.1x bypass tool
{% endembed %}

{% embed url="https://github.com/nccgroup/phantap" %}
An "invisible" network tap aimed at red teams
{% endembed %}

{% embed url="https://github.com/s0lst1c3/silentbridge" %}
802.1x-2010 and 802.1x-2004 bypass toolkit
{% endembed %}

{% embed url="https://github.com/SySS-Research/Lauschgeraet" %}

{% embed url="https://github.com/Zero3K/xsupplicant" %}
802.1X/WPA/WPA2/IEEE802.11i implementation for GNU/Linux/BSD/Windows
{% endembed %}
