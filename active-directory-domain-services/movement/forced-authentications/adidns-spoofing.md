# 🛠️ ADIDNS spoofing

## Theory

In order to function properly, Active Directory services need DNS. In that matter, Active Directory Domain Services \(AD-DS\) offer an integrated storage and replication method for DNS records. This is called Active Directory Integrated DNS \(ADIDNS\).

Just like other domain name resolution spoofing attacks, if an attacker is able to resolve requests with an arbitrary IP address, traffic gets hijacked, the attacker obtains becomes a man-in-the-middle and further attacks can be operated.

Since ADIDNS zone DACL \(Discretionary Access Control List\) enables regular users to create child objects by default, attackers can leverage that and hijack traffic.

ADIDNS zones can be remotely edited either with dynamic updates, or by using LDAP to create dnsNode objects.

## Practice

### Dynamic updates

### LDAP dnsNodes



## References

{% embed url="https://blog.netspi.com/exploiting-adidns/" %}



