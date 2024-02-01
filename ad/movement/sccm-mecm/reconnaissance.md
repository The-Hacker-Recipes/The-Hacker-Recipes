# Reconnaissance

## Theory

SCCM reconnaissance can be performed in many ways. The goal is to enumerate whether SCCM is present in a target network.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
[pxethiefy.py](https://github.com/sse-secure-systems/Active-Directory-Spotlights/tree/master/SCCM-MECM/pxethiefy), which is based on [PXEThief](https://github.com/MWR-CyberSec/PXEThief), can be used to query for PXE boot media

<figure><img src="../../../.gitbook/assets/SCCM_Recon_Linux_pxethiefy.png" alt=""><figcaption></figcaption></figure>

There are a few things to note

* [pxethiefy.py](https://github.com/sse-secure-systems/Active-Directory-Spotlights/tree/master/SCCM-MECM/pxethiefy) uses broadcast requests to request DHCP PXE boot options. An SCCM setup does not have to support PXE boot and a "found" PXE server does not have to be an SCCM component. Be cautious of false positive results.
* In this case a PXE server was found and PXE media was downloaded. The location of the PXE media on the TFTP server is `\SMSTemp\...`, which indicates that this is indeed an SCCM server.

[sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) can also be used to explore the Active Directory and search for SCCM/MECM assets. For this tool, a first user account is required.

```bash
#View the SMB configurations and running services
sccmhunter.py show -smb

#View the users
sccmhunter.py show -user

#View the servers
sccmhunter.py show -computers

#View everything
sccmhunter.py show -all
```
{% endtab %}

{% tab title="Windows" %}
Using LDAP queries from a **domain-joined** Windows machine

```powershell
## LDAP search via PS
PS C:\> ([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties}
```

<figure><img src="../../../.gitbook/assets/SCCM_Recon_ADSI.png" alt=""><figcaption></figcaption></figure>

Using WMI queries or [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) to query a clients local WMI database

```powershell
## WMI
PS C:\> Get-WmiObject -Class SMS_Authority -Namespace root\CCM
## SharmSCCP
PS C:\> .\SharpSCCM.exe local site-info
```

<figure><img src="../../../.gitbook/assets/SCCM_Recon_WMI-SharpSCCM.png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/" %}