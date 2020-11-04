# 🛠️ DNS



{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}



{% tabs %}
{% tab title="UNIX-like" %}
List domain controllers when /etc/resolv.conf is correctly filled with a DNS server \(nameserver\) and a domain name \(search\)

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.$DOMAIN
```
{% endtab %}
{% endtabs %}

