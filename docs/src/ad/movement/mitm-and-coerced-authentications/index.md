---
authors: ShutdownRepo
---

# MITM and coerced auths

In Active Directory domains, attackers often rely on coerced authentications and MitM (man in the middle) techniques to operate lateral movement, especially when attempting authentication relaying attacks (e.g. [NTLM relay](../ntlm/relay.md)) or when [abusing Kerberos delegations](../kerberos/delegations/).

These techniques enable attackers to redirect traffic or redirect/force targets authentications. Attackers will then be able, in certain cases, to capture credentials or relay authentications. I'm using "coerce" instead of "force" in this category's title since some technique can rely on a bit of social engineering to work.

There are many ways attackers can do MitM or redirect/force targets authentications, most of which can be combined for maximum impact (and minimum stealth).

> [!WARNING]
> This page is a work-in-progress

| MITM Technique | [ADIDNS](adidns-spoofing.md) | [LLMNR](llmnr-nbtns-mdns-spoofing.md) | [NBNS](../../recon/nbt-ns.md) | [DHCPv6](dhcpv6-spoofing.md) | [ARP](arp-poisoning.md) | [DNS](dns-spoofing.md) | [WPAD](wpad-spoofing.md) | [PrinterBug](ms-rprn.md) | [PrivExchange](../exchange-services/privexchange.md) |
| --------------------------------------------------------------------- | -------------------------- | ------------------------------------ | ------------------------------------ | --------------------------- | ------------------------------------------------------------------ | ---------------------- | ------------------------ | ------------------------ | -------------------------------- |
| Can require waiting for replication/syncing | x | | | | | | | | |
| Easy to start and stop attacks | | x | x | takes \~5 minutes to revert | revert time depends on targets arp cache timeout (usually \~60 sec | x | x | x | x |
| Exploitable when default settings are present | x | x | x | x | x | x | x | x | up to 2019 |
| Impacts fully qualified name requests | x | not if wildcard ADIDNS record exists | not if wildcard ADIDNS record exists | x | | x | | | |
| Requires constant network traffic for spoofing | | x | x | x | x | x | x | | |
| Requires domain credentials | x | | | | | | | x | requires emails-capable account |
| Requires editing AD | x | | | | | | | | |
| Requires privileged access to launch attack from a compromised system | | x | | | x | x | | | |
| Targets limited to the same network segment as the attacker | | x | x | x | x | | | x | x |
| Disruption | low | low | low | low to high | low to high | low to high | low to high | none | none |


# Coerced auths and Relay

'Coerced authentication' is a technique that, using Windows Remote Procedure Calls (RPCs), forces a service to authenticate against a machine. Using this technique, an attacker can force a vulnerable server to authenticate against a machine controlled by the attacker and in this way, manage to obtain the hash of the machine account password in NetNTLM format.

A machine account in Windows networks refers to a unique identity associated with a device on the network. Machine accounts are essential to establish communication and collaboration between devices within a network environment with Windows operating systems.

The following is a list of the main known vulnerable RPCs for the use of the 'Coerced Authentication' technique:
* [MS-RPRN](ms-rprn.md)
* [MS-EFSR](ms-efsr.md)
* [MS-FSRVP](ms-fsrvp.md)
* [MS-DFSNM](ms-dfsnm.md)

After obtaining an incoming NTLM authentication via SMB protocol from the machine account of a domain controller, through the abuse of techniques known as Coerce, it is possible to relay this authentication to perform certain actions. 

Below are some diagrams of what actions can be performed to compromise a domain depending on the environment:

## NetNTLMv2:
![](<assets/Coerced_SMB_NetNtlmv2_AUTH_Relay.png>)

## NetNTLMv1:
![](<assets/Coerced_SMB_NetNtlmv1_AUTH_Relay.png>)


The explanation of what it is and how to execute the different relay techniques can be found in the following section:
* [NTLM relay](../ntlm/relay.md)
