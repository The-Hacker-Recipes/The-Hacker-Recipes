---
authors: ShutdownRepo
category: web
---

# 🛠️ Insecure deserialization

## Theory

Many web applications manage data and rely on (de)serialization for formatting when storing or sending that data. Applications implementing insecure deserialization means they fail to properly verify and sanitize user inputs that are deserialized, leading to potential DoS (Denial of Service), RCE (Remote Code Execution), logic bugs and so on.

## 🛠️ Practice

Testers need to identify inputs that are serialized (cookies, hidden inputs in forms) and which server-side language is in use : Python, Java, Ruby, PHP.

| Server-side language | Detection                                                                                                                                                                                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Python               | base64 encoded string containing strings like `p0`, `p1`, `g0`, `g1` ...                                                                                                                                                                                                                             |
| Java                 | <p><code>ac ed 00 05</code> magic bytes (hex)<br><code>rO0AB</code> magic bytes (base64)<br><code>H4sIAAAAAAAAAJ</code> magic bytes (gzip(base64))</p><p><code>%C2%AC%C3%AD%00%05</code> magic bytes (URI-encoded)</p><p>Header <code>Content-type="application/x-java-serialized-object"</code></p> |
| Ruby                 | `\x04\bo:\vPerson\x06:\n@nameI\"\x10Luke Jahnke\x06:\x06ET`                                                                                                                                                                                                                                          |
| PHP                  | `a:2:{i:0;s:3:"its";i:1;s:18:"wednesday my dudes";}`                                                                                                                                                                                                                                                 |

The tool [ysoserial](https://github.com/frohoff/ysoserial) (Java) can be used to generate payloads for Java object deserializatio, and [ysoserial.net](https://github.com/pwntester/ysoserial.net) (.net) for .NET object insecure deserialization.

🛠️ Add some examples ?

## Resources

[https://medium.com/blog-blog/insecure-deserialization-e5398e83defea](https://medium.com/blog-blog/insecure-deserialization-e5398e83defea)

[https://www.acunetix.com/blog/articles/what-is-insecure-deserialization/](https://www.acunetix.com/blog/articles/what-is-insecure-deserialization/)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)