---
description: MITRE ATT&CK™ Techniques T1003 and T1552 (kind of)
authors: ShutdownRepo
category: ad
---

# Shuffling

When credentials are found (through [dumping](dumping/) or [cracking](cracking.md) for instance), attackers try to use them to obtain access to new resources and eventually [dump new credentials](dumping/). Those new credentials can then be used to access other resources, eventually find other credentials, and so forth. This process can theoretically be repeated until all resources have been carved out and all credentials have been found.

> I’m calling this section “The Credential Theft Shuffle” (or “Credential Shuffle”) since it is difficult to encapsulate this activity simply. Think of it as a dance. Compromise a single workstation, escalate privileges, and dump credentials. Laterally move to other workstations using dumped credentials, escalate privileges, and dump more credentials.
> 
> This usually quickly results in Domain Admin credentials since most Active Directory admins logon to their workstation with a user account and then use RunAs (which places their admin credentials on the local workstation) or RDP to connect to a server \[...\].
>  
> (quote from Sean Metcalf in [the part 4 "Credential Theft Shuffle" of adsecurity's "Attack Methods for gaining Domain Admin Rights in Active Directory" article](https://adsecurity.org/?p=2362))