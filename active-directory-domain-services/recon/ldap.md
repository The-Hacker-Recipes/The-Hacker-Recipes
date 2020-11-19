# 🛠️ BloodHound

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

[BloodHound](https://github.com/BloodHoundAD/BloodHound) \(Javascript webapp, compiled with Electron, uses [Neo4j](https://neo4j.com/) as graph DBMS\) is an awesome tool that allows to map relationships within Active Directory environments. It mostly uses Windows API functions and LDAP namespace functions to collect data from domain controllers and domain-joined Windows systems.

## Collection

BloodHound needs to be fed JSON files containing info on the objects and relationships within the AD domain. These information are obtained with Ingestors. The best way of doing this is using the official SharpHound \(C\#\) ingestor.

{% tabs %}
{% tab title="Windows" %}
SharpHound \([sources](https://github.com/BloodHoundAD/SharpHound3), [builds](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors)\) is designed targeting .Net 4.5. It can be used as a PowerShell module or as a compiled executable.

It must be run from the context of a domain user, either directly through a logon or through another method such as runas \(`runas /netonly /user:$DOMAIN\$USER`\).

```bash
# Use the PowerShell module
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All

# Use the executable version
.\SharpHound.exe --CollectionMethod All
```

The previous commands are basic but some options \(i.e. Stealth and Loop\) can be very useful depending on the context

```bash
# Perform stealth collection methods
Invoke-BloodHound -CollectionMethod All -Stealth
.\SharpHound.exe --CollectionMethod All --Stealth

# Loop collections (especially useful for session collection)
# e.g. collect sessions every 10 minutes for 3 hours
Invoke-BloodHound -CollectionMethod Session -Loop -LoopDuration 03:00:00 -LoopInterval 00:10:00
.\SharpHound.exe --CollectionMethod Session --Loop --LoopDuration 03:00:00 --LoopInterval 00:10:00

# Use LDAPS instead of plaintext LDAP (IgnoreLdapCert for self-signed TLS/SSL certificates)
Invoke-BloodHound -SecureLdap -IgnoreLdapCert
.\SharpHound.exe --SecureLdap --IgnoreLdapCert
```

{% hint style="success" %}
Here are a few **tips and tricks** on the collection process

* Testers can absolutely run SharpHound from a computer that is not enrolled in the AD domain, by running it in a domain user context \(e.g. with runas, [pass-the-hash](../movement/abusing-ntlm/pass-the-hash.md) or [overpass-the-hash](../movement/abusing-kerberos/overpass-the-hash.md)\). This is useful when domain computers have antivirus or other protections preventing \(or slowing\) testers from using enumerate or exploitation tools.
* When obtaining a foothold on an AD domain, testers should first run SharpHound with all collection methods, and then start a loop collection to enumerate more sessions.
{% endhint %}
{% endtab %}

{% tab title="UNIX-like" %}
From UNIX-like system, a non-official \(but very effective nonetheless\) Python version can be used.

[BloodHound.py](https://github.com/fox-it/BloodHound.py) is a Python ingestor for BloodHound.

```bash
bloodhound.py -c All -d $DOMAIN -u $USERNAME -p $PASSWORD -dc $DOMAIN_CONTROLLER
```

{% hint style="info" %}
This ingestor is not as powerful as the C\# one. It mostly misses GPO collection methods **but** a good news is that it can do pass-the-hash. It becomes really useful when compromising a domain account's NT hash.
{% endhint %}
{% endtab %}
{% endtabs %}

## Analysis

Once collection is over, the data can be uploaded and analyzed in BloodHound.



// how to use BloodHound \(mark as owned, custom queries, delete edges, mark as high value, path finding, what to look for \(i.e. outbound or inbound permissions\), filters, ...\)



{% embed url="https://blog.riccardoancarani.it/bloodhound-tips-and-tricks/" %}





{% embed url="https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/" %}

