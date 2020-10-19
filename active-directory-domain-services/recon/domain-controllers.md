# Domain controllers

{% tabs %}
{% tab title="UNIX-like" %}
List domain controllers when /etc/resolv.conf is correctly filled with a DNS server \(nameserver\) and a domain name \(search\)

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.$DOMAIN
```
{% endtab %}

{% tab title="Windows" %}
From enrolled computer

```bash
echo %LOGONSERVER%

nltest /dclist:$DOMAIN
```
{% endtab %}

{% tab title="nmap" %}
Find LDAP and LDAPS ports \(Kerberos too ?\)

```bash
nmap -sS -p 3268,3269 $IP_RANGE
```
{% endtab %}
{% endtabs %}





