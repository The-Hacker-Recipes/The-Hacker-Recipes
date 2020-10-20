# BloodHound

bloodhound, ingestors etc. Tips \(SharpHound continuous collection, etc.\)

[https://blog.cptjesus.com/posts/newbloodhoundingestor](https://blog.cptjesus.com/posts/newbloodhoundingestor), [https://medium.com/@riccardo.ancarani94/bloodhound-tips-and-tricks-e1853c4b81ad](https://medium.com/@riccardo.ancarani94/bloodhound-tips-and-tricks-e1853c4b81ad),



{% tabs %}
{% tab title="UNIX-like" %}
Python ingestor

[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)

```bash
bloodhound.py -c All -d $DOMAIN -u $USERNAME -p $PASSWORD -dc $DOMAIN_CONTROLLER
```
{% endtab %}

{% tab title="Windows" %}
Compiled C\# or Powershell
{% endtab %}
{% endtabs %}

