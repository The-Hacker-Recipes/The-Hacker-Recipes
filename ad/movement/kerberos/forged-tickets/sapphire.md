# Sapphire tickets

## Theory

Sapphire tickets are similar to [Diamond tickets](diamond.md) in the way the ticket is not forged, but instead based on a legitimate one obtained after a request. The difference lays in how the PAC is modified. The [Diamond ticket](diamond.md) approach modifies the legitimate PAC. In the Sapphire ticket approach, the PAC of another powerful user is obtained through an [S4U2self+u2u](../#s4u2self-+-u2u) trick. This PAC then replaces the one featured in the legitimate ticket. The resulting ticket is an assembly of legitimate elements, and follows a standard ticket request, which makes it then most difficult silver/golden ticket variant to detect.

## Practice

Since Diamond tickets modify PACs on-the-fly to include arbitrary group IDs, chances are some detection software are (of will be) able to detect discrepancies between a PAC's values and actual AD relationships (e.g. a PAC indicates a user belongs to some groups when in fact it doesn't).&#x20;

Sapphire tickets are an alternative to obtaining similar tickets in a stealthier way, by including a legitimate powerful user's PAC in the ticket. There will be no discrepancy anymore between what's in the PAC and what's in Active Directory.

The powerful user's PAC can be obtained through an [S4U2self+u2u](../) trick.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) (Python) script can be used for such purposes with the `-impersonate` argument.

_As of September 25th, 2022, this feature is in a pull request (_[_#1411_](https://github.com/SecureAuthCorp/impacket/pull/1411)_) awaiting to be merged._

The arguments used to customize the PAC will be ignored (`-groups`, `-user-id`, `-extra-sid`,`-duration`), the required domain SID (`-domain-sid`) as well as the username supplied in the positional argument (`baduser` in this case). All these information will be kept as-is from the PAC obtained beforehand using the [S4U2self+u2u](../) trick.

{% code overflow="wrap" %}
```bash
ticketer.py -request -impersonate 'domainadmin' -domain 'DOMAIN.FQDN' -user 'domain_user' -password 'password' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' 'baduser'
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
_At the time of writing this recipe, September 25th, 2022, no equivalent exists for Windows systems._
{% endtab %}
{% endtabs %}
