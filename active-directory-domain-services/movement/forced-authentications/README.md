# Forced authentications

## Theory

In Active Directory domains, attackers often rely on forced authentications and MITM \(man in the middle\) to operate lateral movement, especially when attempting authentication relaying attacks \(e.g. [NTLM relay](../abusing-lm-and-ntlm/ntlm-relay.md)\) or when [abusing Kerberos delegations](../abusing-kerberos/delegations.md).

These techniques enable attackers to redirect traffic or redirect/force targets authentications. Attackers will then be able, in certain cases, to capture credentials or relay authentications.

## Practice

There are many ways attackers can do MITM or redirect/force targets authentications.

## References

{% embed url="https://pentestlab.blog/tag/inveigh/" caption="" %}

{% embed url="https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/" caption="" %}

