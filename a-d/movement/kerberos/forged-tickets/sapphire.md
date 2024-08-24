# Sapphire tickets

## Theory

Sapphire tickets are similar to [Diamond tickets](diamond.md) in the way the ticket is not forged, but instead based on a legitimate one obtained after a request. The difference lays in how the PAC is modified. The [Diamond ticket](diamond.md) approach modifies the legitimate PAC. In the Sapphire ticket approach, the PAC of another powerful user is obtained through an [S4U2self+u2u](../#s4u2self-+-u2u) trick. This PAC then replaces the one featured in the legitimate ticket. The resulting ticket is an assembly of legitimate elements, and follows a standard ticket request, which makes it then most difficult silver/golden ticket variant to detect.

## Practice

Since Diamond tickets modify PACs on-the-fly to include arbitrary group IDs, chances are some detection software are (of will be) able to detect discrepancies between a PAC's values and actual AD relationships (e.g. a PAC indicates a user belongs to some groups when in fact it doesn't).

Sapphire tickets are an alternative to obtaining similar tickets in a stealthier way, by including a legitimate powerful user's PAC in the ticket. There will be no discrepancy anymore between what's in the PAC and what's in Active Directory.

The powerful user's PAC can be obtained through an [S4U2self+u2u](../) trick.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) (Python) script can be used for such purposes with the `-impersonate` argument.

_As of September 11th, 2023, this feature is in a pull request (_[_#1411_](https://github.com/SecureAuthCorp/impacket/pull/1411)_) awaiting to be merged. No_`user-id`_ta bene 1: both the nthash and aeskey must be supplied._\
_Nota bene 2: the `-user-id` argument will be used to build the "Requestor" PAC structure, which could be needed in up-to-date environments (see warning at the bottom of this page)._

The arguments used to customize the PAC will be ignored (`-groups`, `-extra-sid`,`-duration`), the required domain SID (`-domain-sid`) as well as the username supplied in the positional argument (`baduser` in this case). All these information will be kept as-is from the PAC obtained beforehand using the [S4U2self+u2u](../) trick.

{% code overflow="wrap" %}
```bash
ticketer.py -request -impersonate 'domainadmin' \
-domain 'DOMAIN.FQDN' -user 'domain_user' -password 'password' \
-nthash 'krbtgt NT hash' -aesKey 'krbtgt AES key' \
-user-id '1115' -domain-sid 'S-1-5-21-...' \
'baduser'
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
_At the time of writing this recipe, September 25th, 2022, no equivalent exists for Windows systems._
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
In 2021, Microsoft issued a patch ([KB5008380](https://support.microsoft.com/en-gb/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)) for [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) (see [samaccountname-spoofing.md](../samaccountname-spoofing.md)). The patch is explained a bit more in [this blogpost](https://blog.netwrix.com/2022/01/10/pacrequestorenforcement-and-kerberos-authentication/). When the patch entered its enforcement phase (Oct. 11th 2022), it made the Sapphire Ticket attack harder to conduct.

The patch introduced two new structures inside a TGT's PAC: "Requestor" (`PAC_REQUESTOR`) and "Attributes" (`PAC_ATTRIBUTES_INFO`). Those structures are now required in TGTs for all up-to-date environments after the patch enforcement phase, and a `KDC_ERR_TGT_REVOKED` error is raised if a TGT is used without them.

Necessary updates were brought to offensive tooling like [Impacket](https://github.com/fortra/impacket) (PR# [1391](https://github.com/fortra/impacket/pull/1391) and [1545](https://github.com/fortra/impacket/pull/1545)) and [Rubeus](https://github.com/GhostPack/Rubeus) (PR# [105](https://github.com/GhostPack/Rubeus/pull/105)).

However, since the Sapphire Ticket technique relies on a S4U2self + U2U service ticket request to obtain a privileged user's PAC, the PAC doesn't feature the two new "Requestor" and "Attributes" structures. This is probably because the two new structures are only included in TGT's PACs and not service tickets PACs.

When using the Sapphire Ticket technique to forge a TGT, if the two structures are missing from the forget ticket, a `KDC_ERR_TGT_REVOKED` error will be raised in environments that have the patch installed.
{% endhint %}

## Resources

{% embed url="https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/" %}
