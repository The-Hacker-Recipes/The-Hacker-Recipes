Once the Bastion Forest is compromised, there are multiple ways to achieve persistence:
1. One can add a user to an existing Shadow Security Principal Container. `Set-ADObject -Identity "CN=psforest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=defensiveps,DC=local" -Add @{'member'="CN=lowpriv user,CN=Users,DC=defensiveps,DC=local"} -Verbose` 
Please note that in this case, if someone looks at the details of the 'lowprivuser', that account would appear to be a part of the `psforest-ShadowEnterpriseAdmin`'group'.
2. A better and more feasible TTP would be the modification of ACLs of the Shadow Principal Object. One can provide a user in control, Full Permission overt shadow principal object but a principle of minimal permissions should always be met. `Read Members` and `Write Members` permissions on the shadow principal object are adequate to add and remove principals at will from the shadow principals. At this point, one can add or remove users at will with the privileges of 'reportdbadmin' user. On top of that, by default there are no logs for any changes to the ACL or 'membership' of a shadow principal.


{% hint style="info" %}
Please note that the persistence will be for the privileges on the user/production forest and not the Bastion Forest itself.
{% endhint %}
