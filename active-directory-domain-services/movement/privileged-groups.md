# Security groups

## Theory

> In the Windows Server operating system, there are several built-in accounts and security groups that are preconfigured with the appropriate rights and permissions to perform specific tasks. \([Microsoft](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)\)

There are scenarios where testers can obtain full control over members of built-in security groups. The usual targets are members of the "Administrators", "Domain Admins" or "Entreprise Admins" groups, however, other groups can sometimes lead to major privileges escalation.

## Practice

Below is a table summing up some groups' rights and abuse paths.

| Security Group | Rights and abuses |
| :--- | :--- |
| Account Operators | its members can create and manage users and groups, including its own membership and that of the Server Operators group |
| Administrators | full admin rights to the Active Directory domain and Domain Controllers |
| Backup Operators | can backup or restore Active Directory and have logon rights to Domain Controllers |
| Server Operators | its members can sign-in to a server, start and stop services, access domain controllers, perform maintenance tasks \(such as backup and restore\), and they have the ability to change binaries that are installed on the domain controllers |
| DnsAdmins | can read, write, create, delete DNS records \(e.g. edit the [wildcard record](coerced-authentications/adidns-spoofing.md#manual-record-manipulation) if it already exists\). Its members can also [run code via DLL on a Domain Controller operating as a DNS server](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83). |
| Domain Admins | full admin rights to the Active Directory domain, all computers, workstations, servers, users and so on |
| Entreprise Admins | full admin rights to all Active Directory domains in the AD forest |
| Group Policy Creators Owners | create Group Policies in the domain. Its members can't apply group policies to users or group or edit existing GPOs |

## Resources

{% embed url="https://adsecurity.org/?p=3658" %}

