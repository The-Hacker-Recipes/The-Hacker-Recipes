# 🛠️ Domain controllers

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

move this

{% tabs %}
{% tab title="Windows" %}
From enrolled computer

```bash
echo %LOGONSERVER%

nltest /dclist:$DOMAIN
```
{% endtab %}

{% tab title="nmap" %}
Find Kerberos port

```bash
nmap -sS -n --open -p 88 $IP_RANGE
```
{% endtab %}
{% endtabs %}

