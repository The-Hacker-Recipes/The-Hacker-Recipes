# 🛠️ SOCKS proxy

## Theory

SOCKS (SOCKet Secure) is a network protocol that allows users to route network traffic to a server on a client's behalf. SOCKS is between the application and the transport layer of the OSI model.

This is especially useful for penetration testing engagements where a target is hiding behind one or multiple firewalls. A compromised server connected to two networks can be used as a SOCKS proxy server to pivot from a network to another.

In short, a SOCKS proxy can relay TCP and UDP connections and hence help bypass network segmentation. It's sort a dynamic [port forwarding](port-forwarding.md) technique.

## Practice

There are two types of dynamic port forwarding used during penetration testing engagements.

* **Dynamic port forwarding**: tunnel the whole attacker's network traffic (instead of only one port) through a remote machine.
* **Reverse dynamic port forwarding**: tunnel the whole network traffic from a remote machine through the attacker's machine.

### Basic server setup

{% hint style="info" %}
While setting up port forwarding, it's important to remember that non-admin users can only open ports above 1024.
{% endhint %}

In practice, there are many ways to turn a controlled machine into a SOCKS proxy server.

{% tabs %}
{% tab title="SSH commands" %}
One of the most easy is by relying on SSH, however, it requires to have an SSH server running on the controlled machine and a valid account. The tester needs to open an SSH connection to the machine that should be turned into a SOCKS proxy, and supply the `-D` option along with the port to use for tunneling. The command can also be used with `-N` option to make sure no command gets executed after the SSH session is opened.

```bash
ssh -N -D $PORT $CONTROLLED_TARGET
```

Once the ssh command exits successful (or once a session opens) the tester can then proceed to [the usage part](socks-proxy.md#usage).&#x20;

A reverse dynamic port forwarding can be also put in place to tunnel a machine's traffic through the attacker machine. It is implemented entirely in the client (i.e. the server does not need to be updated) ([since OpenSSH 7.6](https://www.openssh.com/txt/release-7.6)).

```bash
ssh -N -R $PORT $CONTROLLED_TARGET
```
{% endtab %}

{% tab title="Chisel" %}
[Chisel](https://github.com/jpillora/chisel) is a standalone binary for pivoting on Linux and Windows systems.

Working on a server/client, the binary simply needs to be uploaded on the victim host and executed as server on the attacker machine.

```bash
# attacker
chisel server --reverse --socks5 -p $PORT

# victim
chisel client $ATTACKER_MACHINE_IP:$ATTACKER_MACHINE_PORT R:socks
```
{% endtab %}

{% tab title="SSH config" %}

{% endtab %}

{% tab title="Metasploit" %}
A meterpreter session can be taken advantage of by setting up a SOCKS proxy with the appropriate module.

The first steps consists in creating a route, from a meterpreter shell to the target

```bash
meterpreter > run autoroute -s 10.11.1.0/24
```

The session can then be put in background and, the SOCKS server can be created.

```bash
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT $PORT
msf > set VERSION 4a
msf > run
```
{% endtab %}

{% tab title="Cobalt Strike" %}

{% endtab %}

{% tab title="proxychains" %}

{% endtab %}

{% tab title="3proxy" %}

{% endtab %}

{% tab title="plink" %}

{% endtab %}
{% endtabs %}

### Basic client usage

Once the SOCKS proxy server is set up, network traffic can be tunneled through with [proxychains-ng](https://github.com/rofl0r/proxychains-ng) (C), a tool still maintained and more advanced based on the original [proxychains](https://github.com/haad/proxychains) (that is not maintained anymore). The port in use by the SOCKS proxy should be supplied in the configuration file (`/etc/proxychains.conf`) like in the following examples.

```bash
# type    ip    port    [user    pass]
socks5    192.168.67.78    1080    lamer    secret
socks4    192.168.11.49    1080
http    192.168.89.33    8080    justu    hidden
http    192.168.39.93    8080
```

### Chaining proxies

In certain scenarios, SOCKS proxies can be chained. This can easily be used with [proxychains](socks-proxy.md#client-usage). In the following example, SSH is used to turn compromised machines into SOCKS proxy servers.

![](<../../.gitbook/assets/multi-port-forwarding-Dynamic Port Forwarding.png>)

![Setting up the SOCKS proxy servers (with SSH)](<../../.gitbook/assets/carbon(3) (1).png>)

![Setting up the SOCKS proxy client (proxychains)](<../../.gitbook/assets/carbon(1) (1).png>)

![Attacking the target through the chain of SOCKS proxies](<../../.gitbook/assets/carbon(4) (1).png>)

