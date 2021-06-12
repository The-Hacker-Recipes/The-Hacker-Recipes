# 🛠️ HTTP verb tampering

## Theory

Some web servers filter access to resources based on HTTP verbs. The HTTP verb tampering attack makes use of a weak access control mechanism: if a resource can be accessed only by an admin with a GET verb, non-admin shouldn't be able to do the same. However, in case of misconfiguration, a non-admin user could potentially use another verb such as HEAD to access the resource.

## Practice

Testing for HTTP verb tampering with [httpmethods](https://github.com/ShutdownRepo/httpmethods).

```bash
httpmethods -u $URL
```

