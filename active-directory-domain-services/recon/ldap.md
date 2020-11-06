# 🛠️ LDAP

A lot of information can be obtained through Metadata \(naming contexts, dns server name, domain functional level\) will be obtainable anonymously, even with anonymous binding disabled.

## Basic enumeration

The tool windapsearch \([Go](https://github.com/ropnop/go-windapsearch) \(preferred\) or [Python](https://github.com/ropnop/windapsearch)\) can be used to enumerate basic but useful information.

```bash
# enumerate users (authenticated bind)
windapsearch -d $DOMAIN -u $USER -p $PASSWORD --dc $DomainController --module users

# enumerate users (anonymous bind)
windapsearch --dc $DomainController --module users

# obtain metadata (anonymous bind)
windapsearch --dc $DomainController --module metadata
```

{% hint style="info" %}
LDAP anonymous binding is usually disabled but it's worth checking. It could be handful to list the users and test for [ASREProasting](../movement/abusing-kerberos/asreproast.md) \(since this attack needs no authentication\).
{% endhint %}

## Advanced enumeration \(BloodHound\)

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

[BloodHound](https://github.com/BloodHoundAD/BloodHound) \(Javascript webapp, compiled with Electron, uses [Neo4j](https://neo4j.com/) as graph DBMS\) is an awesome tool that allows to map relationships within Active Directory environments.

### Collection

// how to collect info \(SharpHound, bloodhound.py, ...\)

{% tabs %}
{% tab title="UNIX-like" %}
Python ingestor

[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)

```bash
bloodhound.py -c All -d $DOMAIN -u $USERNAME -p $PASSWORD -dc $DOMAIN_CONTROLLER
```
{% endtab %}

{% tab title="Windows" %}
Compiled C\# or Powershell
{% endtab %}
{% endtabs %}

### Analysis

// how to use BloodHound \(mark as owned, custom queries, delete edges, mark as high value, path finding, what to look for \(i.e. outbound or inbound permissions\), filters, ...\)









Move this to LDAP

bloodhound, ingestors etc. Tips \(SharpHound continuous collection, etc.\)

{% embed url="https://blog.cptjesus.com/posts/newbloodhoundingestor" %}



{% embed url="https://blog.riccardoancarani.it/bloodhound-tips-and-tricks/" %}





{% embed url="https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/" %}

