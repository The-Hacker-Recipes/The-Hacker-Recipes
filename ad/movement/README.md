# Movement

{% hint style="danger" %}
**This is a work-in-progress**
{% endhint %}

Below is a checklist to go through when conducting a pentest. Order is irrelevant and many tests require authenticated or admin access. This checklist answers "what to audit on AD?" rather than "how to pwn AD?". A mindmap is in the works for that matter :wink: .&#x20;

### NTLM configuration

* [ ] Obsolete versions of this protocol (LM, LMv2 and NTLM(v1)) are disabled and NTLM (all versions) is disabled when possible. This allows to stay safe from [NTLM relay](ntlm/relay.md), [NTLM capture](ntlm/capture.md) and [cracking](credentials/cracking.md#tips-and-tricks) and [pass-the-hash](ntlm/pth.md) attacks.

### Kerberos configuration

* [ ] `krbtgt`'s password has been changed in the last 6 months to prevent [Golden Ticket](../persistence/silver-and-golden-tickets.md) persistence attacks. From UNIX-like systems, this can be checked with [Impacket](https://github.com/SecureAuthCorp/impacket/)'s [Get-ADUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetADUsers.py) script.
* [ ] The RC4 `etype` is disabled for Kerberos to prevent [overpass-the-hash](kerberos/opth.md) and [NTLMv1 capture](ntlm/capture.md) and [cracking](credentials/cracking.md#tips-and-tricks) to [Silver Ticket](../persistence/silver-and-golden-tickets.md) attacks. This can be checked by attempting to obtain a TGT with an NT hash.
* [ ] No account is configured with `Do not require Kerberos Pre-Authentication` allowing for [ASREProast](kerberos/asreproast.md) attacks, or make sure those account have strong password resistant to [cracking](credentials/cracking.md).
* [ ] User accounts that have at least one `ServicePrincipalName`, hence vulnerable to [Kerberoast](kerberos/kerberoast.md), have a strong password, resistant to [cracking.](credentials/cracking.md)

### Patch management

* [ ] Domain Controllers are patched against [ZeroLogon](netlogon/zerologon.md).
* [ ] Domain Controllers are patched against [Kerberos sAMAccountName spoofing](kerberos/samaccountname-spoofing.md).
* [ ] [MS14-068](kerberos/forged-tickets/#ms-14-068-cve-2014-6324) is patched, preventing forging of powerful Kerberos tickets.
* [ ] [PrivExchange](exchange-services/privexchange.md) patches are applied, protecting Exchange servers from [authentication coercion attacks relying on the PushSubscription API](mitm-and-coerced-authentications/pushsubscription-abuse.md), and [ACE abuse](dacl/) attacks relying on the `EXCHANGE WINDOWS PERMISSION` group having `WriteDacl` permissions against the domain object allowing for [DCSync](credentials/dumping/dcsync.md).
* [ ] Patches for NTLM tampering vulnerabilities (e.g. CVE-2019-1040, CVE-2019-1019, CVE-2019-1166) are applied to limit [NTLM relay](ntlm/relay.md) attacks.
* [ ] Latest security patched are applied (e.g. for ProxyLogon, ProxyShell, PrintNightmare, ...).

### Access Management (IAM/PAM)

* [ ] Local administrators have a unique, random, complex and rotating password on every server/workstation (e.g. use of LAPS). This can be checked by dumping a local admin password or hash and attempting [credential stuffing](credentials/bruteforcing/stuffing.md) (i.e. trying to log in on other resources with that password/hash).
* [ ] Strong [password and lockout policies](../recon/password-policy.md) exist and are applied (complexity enabled, at least 12 chars, 16 for admins, must change every 6 months) and users know not to use simple and guessable passwords (e.g. password == username) limiting credential [bruteforcing](credentials/bruteforcing/), [guessing](credentials/bruteforcing/guessing.md), [stuffing](credentials/bruteforcing/stuffing.md) and [cracking](credentials/cracking.md) attacks.
* [ ] Tier Model is applied (administrative personnel have multiple accounts, one for each tier, with different passwords and security requirements for each one) and a "least requirement" policy is followed (i.e. service accounts don't have domain admin (or equivalent) privileges, ACEs are carefully set) limiting credential [bruteforcing](credentials/bruteforcing/), [guessing](credentials/bruteforcing/guessing.md), [stuffing](credentials/bruteforcing/stuffing.md) and [cracking](credentials/cracking.md) attacks.
* [ ] Sensitive network shares are not readable by all users. A "need to know" policy is followed, preventing data leak and other [credential-based attacks](credentials/).
* [ ] No account is configured with [Kerberos Unconstrained Delegation](kerberos/delegations/#unconstrained-delegations) capabilities.
* [ ] No computer account has admin privileges over another one. This limits [NTLM relay](ntlm/relay.md) attacks.

### Credentials Management

* [ ] Caching of domain users is limited on workstations and avoided on servers to prevent [credential dumping](credentials/dumping/) of LSA secrets from registry.
* [ ] [Group Policy Preferences Passwords](credentials/dumping/group-policies-preferences.md) are not used.
* [ ] LSA protection are enabled to prevent [LSASS dumping](credentials/dumping/lsass.md).
* [ ] Network shares readable by all domain users don't contain sensitive data like passwords or certificates limiting [credential dumping](credentials/dumping/network-shares.md).

### Domain-level configuration and best-practices

* [ ] The [Machine Account Quota](domain-settings/machineaccountquota.md) domain-level attribute is set to 0, preventing domain users from creating domain-joined computer accounts.
* [ ] Default [special groups](domain-settings/builtin-groups.md) are empty, limiting, among other things, out-of-box ACE abuses.

### Networking, protocols and services

* [ ] SMB is required when possible, especially on sensitive servers, preventing [NTLM relay](ntlm/relay.md) attacks.
* [ ] LDAP signing is required on Domain Controllers, preventing [NTLM relay](ntlm/relay.md) attacks.
* [ ] Extended Protection for Authentication (EPA) is required, especially for Domain Controllers supporting LDAPS, preventing [NTLM relay](ntlm/relay.md) attacks.
* [ ] IPv6 is either fully configured and used or disabled, preventing [DHCPv6 spoofing with DNS poisoning](mitm-and-coerced-authentications/dhcpv6-spoofing.md) attacks.
* [ ] [LLMNR, NBT-NS and mDNS](mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing.md) are disabled, preventing MITM attacks relying on those multicast/broadcast domain name resolution protocols.
* [ ] WPAD is disabled, preventing [WPAD spoofing](mitm-and-coerced-authentications/wpad-spoofing.md).
* [ ] A record exists in ADIDNS for the `*` (wildcard) preventing powerful [ADIDNS poisoning](mitm-and-coerced-authentications/adidns-spoofing.md#wildcard-records) attacks. Preferably, this is a `TXT` record.
* [ ] The print spooler is disabled on Domain Controllers and sensitive servers to prevent the [PrinterBug](print-spooler-service/printerbug.md) authentication coercion attack.
* [ ] The WSUS server (if any) is configured with HTTPS, to prevent ARP poisoning with [WSUS spoofing](mitm-and-coerced-authentications/wsus-spoofing.md) attacks.
* [ ] Set-up packet filtering & inspection and enable port security on network switched to prevent [ARP poisoning](mitm-and-coerced-authentications/arp-poisoning.md) attacks and [network secrets dumping](credentials/dumping/network-protocols.md).&#x20;
* [ ] Set-up VLANs, 802.1X or other [NAC (Network Access Control)](../../physical/networking/network-access-control.md) securities to limit the attackers progress within the network.
* [ ] Plaintext protocols are avoided when using credentials (HTTP, FTP, ...), in order to minimize the risks of the [capture of credentials transiting on the network](credentials/dumping/network-protocols.md).

### Active Directory Certificate Services

* [ ] The CA is configured correctly (the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is not set). This prevents [the corresponding domain escalation attack](ad-cs/ca-configuration.md).
* [ ] There are no certificate templates that are badly configured. This prevents [the corresponding domain escalation attack](ad-cs/certificate-templates.md).
* [ ] AD-CS web endpoints are secured against [AD-CS NTLM relay attacks](ad-cs/web-endpoints.md) (HTTPS and EPA (Extended Protection for Authentication) enforced).

