# Delegations

The authentication protocol "Kerberos" features delegation capabilities described as follows. There are three types of Kerberos delegations

* **Unconstrained delegations \(KUD\)**: a service can impersonate users on any other service.
* **Constrained delegations \(KCD\)**: a service can impersonate users on a set of services
* **Resource based constrained delegations \(RBCD\)** : a set of services can impersonate users on a service

{% hint style="info" %}
With constrained and unconstrained delegations, the delegation attributes are set on the impersonating service whereas with RBCD, these attributes are set on the final resource or computer account itself.
{% endhint %}

Kerberos delegations can be abused by attackers to obtain valuable assets and sometimes even domain admin privileges.

{% hint style="info" %}
A mindmap about this is in progress...
{% endhint %}

Some of the following parts allow to obtain modified or crafted Kerberos tickets. Once obtained, these tickets can be used with [Pass-the-Ticket](../pass-the-ticket.md).

{% page-ref page="unconstrained.md" %}

{% page-ref page="constrained.md" %}

{% page-ref page="rbcd.md" %}

