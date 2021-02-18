# 🛠️ MachineAccountQuota





```bash
import ldap3
target_dn = "" # something like 'DC=domain,DC=local'
domain = "domain"
username = "username"
user = "{}\\{}".format(domain, username)
password = "password"
server = ldap3.Server(domain)
connection = ldap3.Connection(server = server, user = user, password = password, authentication = NTLM)
connection.bind()
connection.search(target_dn,"(objectClass=*)", attributes=['ms-DS-MachineAccountQuota'])
print(connection.entries)
```

{% hint style="danger" %}
**his is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

[https://blog.netspi.com/machineaccountquota-is-useful-sometimes/](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)

