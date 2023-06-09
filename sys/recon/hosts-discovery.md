# 🛠️ Hosts discovery

## Theory

When targeting machines connected to a network, identifying which hosts are up and running (and their IP address) is the first step in getting to know the attack surface. There are multiple active and passive ways to discover hosts in a network, each relying on specific protocols that may be used in the network.

Once the hosts are identified, attackers then usually proceed to [port scanning](port-scanning.md) to attempt at compromising them.

Alternatively, there are common scenarios where most of the hosts and services are managed by a central set of services like [Active Directory Domain Services (AD-DS)](broken-reference/). In this case, attackers usually try to compromise those services first as it would grant them control over many hosts without having to attack them all. A whole category of The Hacker Recipes is dedicated to Active Directory Domain Services (and other associated AD services).

## Practice

//// WIP : add p0f, bettercap

### ARP discovery

```bash
# (active) scan all private ranges (i.e. 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
netdiscover -i $INTERFACE

# (active) scan a given range (e.g. 192.168.0.0/24)
netdiscover -i $INTERFACE -r $RANGE

# passive scan (doesn't send packets)
netdiscover -i $INTERFACE -p

# (active) scan a given range
nmap -sn $RANGE
```

### NBT discovery

It sends NetBIOS status query to each address in supplied range and lists received information in human readable form. For each responded host it lists IP address, NetBIOS computer name, logged-in user name and MAC address (such as Ethernet).

```bash
nbtscan -r $RANGE
```

### DNS queries

In Active Directory environnements, machines have their record on the Domain Controller (which usually hosts the DNS service). Through PTR resolution requests, is it then possible to find additional ranges and machines.

{% content-ref url="../../ad/recon/dns.md" %}
[dns.md](../../ad/recon/dns.md)
{% endcontent-ref %}

### ICMP discovery

```bash
# Send one echo request to a host
(Windows) ping -n 1 $HOST
(UNIX) ping -c 1 $HOST

# Send echo requests to ranges
fping -g $RANGE

# Send ICMP echo, timestamp, and netmask request discovery probes to a range
nmap -PE -PP -PM -sP $RANGE
```

Ping Sweep on Powershell:

{% code overflow="wrap" %}
```powershell
$ping = New-Object System.Net.Networkinformation.Ping ; 1..254 | % { $ping.send("192.168.0.$_", 1) | where status -ne 'TimedOut' | select Address | fl * }
```
{% endcode %}

### ICMPv6 discovery

```bash
```

## Resources

{% embed url="https://book.hacktricks.xyz/pentesting/pentesting-network#passive" %}
