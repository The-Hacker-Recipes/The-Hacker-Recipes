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

### Wildcard recon

On Windows, the [Powermad ](https://github.com/Kevin-Robertson/Powermad)module can be used to resolve names \(all DNS spoofing attacks need to be stopped in order to avoid false results\).

```bash
Resolve-DnsName NameThatDoesntExist
```

That command will either return an IP address, indicating that the wildcard record exists \(or that `NameThatDoesntExist` is an actual explicit record\), or return an error stating that the DNS name doesn't exist, indicating that the wildcard record doesn't exist.

### Manuel record addition

On Windows, the [Powermad ](https://github.com/Kevin-Robertson/Powermad)module can be used to manually add a record to an ADIDNS zone.

The following commands creates a wildcard record and sets the `dNSTombstoned` attribute, allowing any authenticated user to perform modifications to the node \(this helps maintain control of the node, even when the owner accounts gets deleted. Pretty useful after a pentest\).

```text
New-ADIDNSNode -Node * -Tombstone -Verbose
```

More help on usage, support functions, parameters and attacks [here](https://github.com/Kevin-Robertson/Powermad#adidns-functions).

### Dynamic spoofing

The following command will 

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

* `Clear-Inveigh` to clear the $inveigh hashtable
* `Get-Inveigh` to get data from the $inveigh hashtable
* `Stop-Inveigh` to stop all running Inveigh modules
* `Watch-Inveigh` to enable real time console output

## References

{% embed url="https://blog.netspi.com/exploiting-adidns/" %}

{% embed url="https://blog.netspi.com/adidns-revisited/" %}

