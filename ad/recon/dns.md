# DNS

## Finding Domain Controllers

AD-DS (Active Directory Domain Services) rely on DNS SRV RR (service location resource records). Those records can be queried to find the location of some servers: the global catalog, LDAP servers, the Kerberos KDC and so on.&#x20;

{% tabs %}
{% tab title="dnsutils" %}
nslookup is a DNS client that can be used to query SRV records. It usually comes with the [dnsutils](https://packages.debian.org/buster/dnsutils) package.

```bash
# find the PDC (Principal Domain Controller)
nslookup -type=srv _ldap._tcp.pdc._msdcs.$FQDN_DOMAIN

# find the DCs (Domain Controllers)
nslookup -type=srv _ldap._tcp.dc._msdcs.$FQDN_DOMAIN

# find the GC (Global Catalog, i.e. DC with extended data)
nslookup -type=srv gc._msdcs.$FQDN_DOMAIN

# Other ways to find services hosts that may be DCs 
nslookup -type=srv _kerberos._tcp.$FQDN_DOMAIN
nslookup -type=srv _kpasswd._tcp.$FQDN_DOMAIN
nslookup -type=srv _ldap._tcp.$FQDN_DOMAIN
```

The same commands can be operated the old way with nslookup.
{% endtab %}

{% tab title="nmap" %}
The [nmap](https://nmap.org/) tool can be used with its [dns-srv-enum.nse](https://nmap.org/nsedoc/scripts/dns-srv-enum.html) script to operate those queries.

```bash
nmap --script dns-srv-enum --script-args dns-srv-enum.domain=$FQDN_DOMAIN
```
{% endtab %}
{% endtabs %}

In order to function properly, the tools need to know the domain name and which nameservers to query. That information is usually [sent through DHCP offers](dhcp.md) and stored in the `/etc/resolv.conf` or `/run/systemd/resolve/resolv.conf` file in UNIX-like systems.&#x20;

If needed, the nameservers may be found with a port scan on the network by looking for DNS ports `53/TCP` and `53/UDP`.

```bash
nmap -v -sV -p 53 $SUBNET/$MASK
nmap -v -sV -sU -p 53 $SUBNET/$MASK
```

{% hint style="info" %}
The DNS service is usually offered by the domain controllers
{% endhint %}

{% embed url="https://petri.com/active_directory_srv_records" %}

## Reverse lookups

In Active Directory Integrated DNS, reverse lookup zones are used to resolve IP addresses to hostnames. This operation relies on DNS PTR records. This allows to find the names of the hosts in a network. The presence of reverse lookup zones is not mandatory in Active Directory, hence limiting reverse lookup capabilities.

```bash
# standard lookup
host $hostname

# reverse lookup
host $IP_address

# manual PTR resolution request
nslookup -type=ptr $IP_address

# PTR restolution on a range
dnsrecon -r $RANGE -n $DC_IP
```
