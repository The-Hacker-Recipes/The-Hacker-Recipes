# DHCP poisoning

## Theory

When a workstation reboots or plugs into a network, a broadcast DHCP request is emitted. It's goal is to ask for network settings like an IPv4 address.

> Windows uses several custom DHCP options such as NetBIOS, WINS, WPAD settings. When a workstation sends a DHCP request to get its networking settings, these additional settings can be included in the DHCP answer to facilitate straightforward connectivity and name resolution. _(_[_Laurent Gaffié_](https://g-laurent.blogspot.com/2021/08/responders-dhcp-poisoner.html)_)_

[DHCP's option 252](https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb794881\(v=technet.10\)) provides Windows machines with a WPAD configuration. An attacker able to answer broadcast DHCP queries faster than the legit DHCP server can inject any network setting on the requesting client.

## Practice

[Responder](https://github.com/SpiderLabs/Responder) (Python) can be used to operate DHCP poisoning in the following manner

* race against the legit DHCP server to answer `DHCP REQUEST` messages
* sent a DHCP ACK response with a rogue WPAD server address in `option 252` in the network parameters, with a short lease (10 seconds). Responder can also be used to attempt at injecting a DNS server instead.
* wait the lease to expire so that the poisoned client asks for a new lease
* let the client obtain a legitimate lease from the real DHCP server, allowing the client to obtain the right network settings and have connectivity
* the injected WPAD server address will stay until the client reboots. If the injected field was a DNS server, it will be overwritten with the new legit DHCP lease.
* with the injected WPAD server address, the Windows client will try to obtain the `wpad.dat` file on the rogue WPAD. Responder will then require the client to authenticate.

The attack can be started with the `-d/--DHCP` (WPAD injection) argument. By default, a rogue WPAD server will be injected in the configuration. If the additional`-D/--DHCP-DNS` argument is set, a rogue DNS server address will be injected in the configuration instead of a WPAD.

Additional arguments and options should be used when doing DHCP poisoning with the `-d/--DHCP` argument. Those options can also be used along `-D/--DHCP-DNS` since the WPAD DNS entry will be one of the first queries by the poisoned machine.

* The `-w/--wpad` option to start the WPAD rogue server so that fake `wpad.dat` file can be served to requesting clients (i.e. [WPAD spoofing](wpad-spoofing.md))
* The `-P/--ProxyAuth` option to force the Windows client to authenticate after the `wpad.dat` is accessed and when the client starts using the proxy

```bash
# DNS injection
responder --interface "eth0" --DHCP --DHCP-DNS --wpad --ProxyAuth
responder -I "eth0" -wPdD

# WPAD injection
responder --interface "eth0" --DHCP --wpad --ProxyAuth
responder -I "eth0" -wPd
```

{% hint style="info" %}
The proxy auth NTLM authentication can either be

* forced and [captured](../ntlm/capture.md) with Responder with the command line above (with `--wredir` and `--ProxyAuth`)
* or forced and [relayed](../ntlm/relay.md) with [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (by using the `--http-port 3128` argument

```bash
responder --interface "eth0" --DHCP --DHCP-DNS --wpad
ntlmrelayx -t $target --http-port 3128
```
{% endhint %}

## Resources

{% embed url="https://g-laurent.blogspot.com/2021/08/responders-dhcp-poisoner.html" %}

