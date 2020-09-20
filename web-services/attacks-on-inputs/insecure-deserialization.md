# 🛠️ Insecure deserialization

## Theory

Many web applications manage data and rely on \(de\)serialization for formatting when storing or sending that data. Applications implementing insecure deserialization means they fail to properly verify and sanitize user inputs that are deserialized, leading to potential DoS \(Denial of Service\), RCE \(Remote Code Execution\), logic bugs and so on.

## 🛠️ Practice

Testers need to identify inputs that are serialized \(cookies, hidden inputs in forms\) and which server-side language is in use : Python, Java, Ruby, PHP.

<table>
  <thead>
    <tr>
      <th style="text-align:left">Server-side language</th>
      <th style="text-align:left">Detection</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Python</td>
      <td style="text-align:left">base64 encoded string containing strings like <code>p0</code>, <code>p1</code>, <code>g0</code>, <code>g1</code> ...</td>
    </tr>
    <tr>
      <td style="text-align:left">Java</td>
      <td style="text-align:left">
        <p><code>ac ed 00 05</code> magic bytes (hex)
          <br /><code>rO0AB</code> magic bytes (base64)
          <br /><code>H4sIAAAAAAAAAJ</code> magic bytes (gzip(base64))</p>
        <p><code>%C2%AC%C3%AD%00%05</code> magic bytes (URI-encoded)</p>
        <p>Header <code>Content-type=&quot;application/x-java-serialized-object&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Ruby</td>
      <td style="text-align:left"><code>\x04\bo:\vPerson\x06:\n@nameI\&quot;\x10Luke Jahnke\x06:\x06ET</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">PHP</td>
      <td style="text-align:left"><code>a:2:{i:0;s:3:&quot;its&quot;;i:1;s:18:&quot;wednesday my dudes&quot;;}</code>
      </td>
    </tr>
  </tbody>
</table>

The tool [ysoserial](https://github.com/frohoff/ysoserial) \(Java\) can be used to generate payloads for Java object deserialization.

🛠️ Add some examples ?

## References

{% embed url="https://medium.com/blog-blog/insecure-deserialization-e5398e83defea" caption="" %}

{% embed url="https://www.acunetix.com/blog/articles/what-is-insecure-deserialization/" caption="" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization" caption="" %}

