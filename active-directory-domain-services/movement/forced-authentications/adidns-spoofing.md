# 🛠️ ADIDNS spoofing

## Theory

In order to function properly, Active Directory services need DNS. In that matter, Active Directory Domain Services \(AD-DS\) offer an integrated storage and replication method for DNS records. This is called Active Directory Integrated DNS \(ADIDNS\).

Just like other domain name resolution spoofing attacks, if an attacker is able to resolve requests with an arbitrary IP address, traffic gets hijacked, the attacker obtains becomes a man-in-the-middle and further attacks can be operated.

Since ADIDNS zone DACL \(Discretionary Access Control List\) enables regular users to create child objects by default, attackers can leverage that and hijack traffic.

ADIDNS zones can be remotely edited

* with **dynamic updates** \(a DNS specific protocol used by machine accounts to add and update their own DNS records\). Users can create records if they don't exist, and they will have full control over it. By default, users that don't own a record will not be able to edit it, or to add another one with the same name, even if the type is different \(A, AAAA, CNAME, MX, and so on\).
* by **using LDAP** to create dnsNode objects. While dynamic updates can't be used to inject a wildcard DNS record, LDAP can \(only if the record doesn't already exist, which is the case by default\).

> Wildcard records allow DNS to function in a very similar fashion to LLMNR/NBNS spoofing. Once you create a wildcard record, the DNS server will use the record to answer name requests that do not explicitly match records contained in the zone. \([source](https://blog.netspi.com/exploiting-adidns/#wildcard)\)

## Practice

On Windows, the [Powermad ](https://github.com/Kevin-Robertson/Powermad)module can be used to resolve names \(all DNS spoofing attacks need to be stopped in order to avoid false results\).

```bash
Resolve-DnsName NameThatDoesntExist
```

That command will either return an IP address, indicating that the wildcard record exists \(or that `NameThatDoesntExist` is an actual explicit record\), or return an error stating the DNS name doesn't exist, indicating that the wildcard record doesn't exist.



## References

{% embed url="https://blog.netspi.com/exploiting-adidns/" %}



