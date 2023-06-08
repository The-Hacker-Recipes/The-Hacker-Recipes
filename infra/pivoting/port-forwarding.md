# 🛠️ Port forwarding

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name. Need to do some SSH config work
{% endhint %}

## Theory

Port forwarding is a pivoting technique that allows network packets to be relayed from a port to another. The tunnel can be setup between two controlled and connected machines, hence allowing a bridge between a network and another. That concept is similar to PAT (Port Address Translation), an extension of NAT (Network Address Translation) that allows multiple devices on a LAN to be mapped to a single public IP address by assigning addresses to ports numbers.

This technique is useful when an attacker wants to stay under the radar or when access to a service is limited to a specific network.

## Practice

There are multiple types of port forwarding used during penetration testing engagements.

* **Local port forwarding**: access a port that only a remote machine can communicate with (e.g. "firewalled" network, internal localhost network).
* **Remote port forwarding**: access an attacker's service (from the attacker's machine's networks) from a remote workstation that can't access those networks directly.
* **Dynamic port forwarding**: tunnel the whole attacker's network traffic (instead of only one port) through a remote machine. Explained in [SOCKS proxy](socks-proxy.md).
* **Reverse dynamic port forwarding**: tunnel the whole network traffic from a remote machine through the attacker's machine. Explained in [SOCKS proxy](socks-proxy.md).

### Basic setup

{% hint style="info" %}
While setting up port forwarding, it's important to remember that non-admin users can only open ports above 1024.
{% endhint %}

Port forwarding can be set up in many different ways.

{% tabs %}
{% tab title="SSH" %}
## SSH commands

One of the most easy is by relying on SSH however, it requires to have an SSH server running on the controlled machine and a valid account. The tester needs to open an SSH connection to the machine that should be turned into a SOCKS proxy, and supply&#x20;

* the `-L` option for a local port forwarding, along with the ports and addresses to bind
* the `-R` option for a remote port forwarding, along with the ports and addresses to bind

The command can also be used with `-N` option to make sure no command gets executed after the SSH session is opened.

```bash
# Local port forwarding
ssh -N -L $LOCAL_ADDRESS:$LOCAL_PORT:$REMOTE_ADDRESS:$REMOTE_PORT user@target

# Remote port forwarding
ssh -N -R $REMOTE_ADDRESS:$REMOTE_PORT:$LOCAL_ADDRESS:$LOCAL_PORT user@target
```

Once the ssh command exits successful (or once a session opens) the tester can then proceed to use the tunnel.



## SSH configs

The same operations can be conducted through a pre-configured agent instead of using command-line argument. TODO
{% endtab %}

{% tab title="Chisel" %}
Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network.

```bash
# Attacker machine
chisel server -p $ATTACKER_PORT -reverse
# Victime machine
.\chisel.exe client $ATTACKER_IP:$ATTACKER_PORT R:$REMOTE_PORT:localhost:$LOCAL_PORT
```

{% hint style="info" %}
Chisel binaries can be downloaded from [the official GitHub repository](https://github.com/jpillora/chisel/releases).
{% endhint %}
{% endtab %}

{% tab title="Metasploit" %}
Meterpreter features built in port forwarding capabilities with the `portfwd` cmdlet.

* the `-l` option for a local port forwarding, along with the ports and addresses to bind.
* the `-p` option for a remote port forwarding, along with the ports and addresses to bind.
* the `-r` option for the targeted remote machine IP address.

```bash
# Add port forward
portfwd add –l $LOCAL_PORT –p $REMOTE_PORT –r $REMOTE_ADDRESS

# List ports forwarded
portfwd list

# Delete port forwarded
portfwd delete –l $LOCAL_PORT –p $REMOTE_PORT –r $REMOTE_ADDRESS

# Remove all port forwarded
portfwd flush
```
{% endtab %}

{% tab title="plink" %}
TODO
{% endtab %}

{% tab title="nc" %}
From a UNIX-like host, the `nc` utility can be used to setup local port forwarding.

```bash
nc -lvk $LOCAL_ADDRESS $LOCAL_PORT -c "nc -v $REMOTE_ADDRESS $REMOTE_PORT"
```
{% endtab %}

{% tab title="ngrok" %}
[Ngrok](https://github.com/inconshreveable/ngrok) (Go) is a tool that allows to expose a local web server to the Internet. Upon command execution, the tool will output the Internet-facing address that's configured for port forwarding to the local service.

```bash
# Expose a local HTTP service on a given port:
ngrok http $LOCAL_PORT

# Expose a local HTTPS server:
ngrok http https://localhost

# Expose raw TCP traffic on a given port:
ngrok tcp $LOCAL_PORT
```
{% endtab %}
{% endtabs %}

### Chained local port forwarding

In the following example (real-world badly secured network), let's assume the remote attacker wants to access a internal workstation's web service (i.e. localhost), and that the attackers controls multiple machines that can bridge the multiple networks at play.

![](<../../.gitbook/assets/multi-port-forwarding-Local Port Forwarding.png>)

![Setting up the pivoting points](../../.gitbook/assets/carbon\(8\).png)

This setup allows the attackers to connect to the workstation web-service on port `80/TCP` by targeting port `1111/TCP` on his own machine. His machine will forward the communication to pivot1's port `2222/TCP`. Pivot1 will forward to pivot2's `3333/TCP`. Pivot2 will forward to workstation's `80/TCP`.

### Chained remote port forwarding

In the following example (real-world badly secured network), let's assume the remote attacker wants a target workstation to connect back to him with a reverse shell, and that the attackers controls multiple machines that can bridge the multiple networks at play. There are multiple scenarios where using a combination of remote port forwarding would be interesting or even required.

* the attacker wants to stay stealthy by using multiple specific hops to make the traffic legitimate-looking (workstation communicates with an internal server, an internal server communicates with a DMZed server, a DMZed server communicates with a remote client)
* the target workstation doesn't have access to the remote attacker's network (i.e. to the Internet)

![](<../../.gitbook/assets/multi-port-forwarding-Remote Port Forwarding.png>)

![Setting up the pivoting points](../../.gitbook/assets/carbon\(6\).png)

This setup allows the target workstation to communicate with the attacker's port `1111/TCP` by targeting pivot2 on port `3333/TCP`. Pivot2 will forward the communication to pivot1's port `2222/TCP` which will itself forward to attacker's port `1111/TCP`.

{% hint style="info" %}
If ports are only opened on the loopback interface, testers should make sure the `/etc/ssh/sshd_config` has the `GatewayPorts` option set to `yes` or `clientspecified`.
{% endhint %}
