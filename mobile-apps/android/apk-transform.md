---
description: Pimp my APK
---

# APK transform

## Theory

An .APK file (e.g. Android Package) is a compressed collection of files (i.e. a package) for Android. It could be extracted as an regular archive.

A .DEX file (.e.g Dalvik EXecutable) is an executable file saved in a format that contains compiled code that Android systems can run.

When auditing an APK, transforming it to human-readable formats is usually required.

* [smali](https://github.com/JesusFreke/smali) and [baksmali](https://github.com/JesusFreke/smali) are DEX assembler and disassembler respectively
* [d2j-dex2jar](https://github.com/pxb1988/dex2jar) can be used to convert DEX files to .class files (zipped as .jar)
* [jadx](https://github.com/skylot/jadx) is a DEX to Java decompiler. It can be used in CLI and GUI for producing Java source code out of Android DEX and APK files.

## Practical

<details>

<summary>Install notes</summary>

## Add Kali repo to your sources

{% code overflow="wrap" %}
```
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" >>  /etc/apt/sources.list 

apt-get update
```
{% endcode %}

Note that if you haven’t updated your Kali installation in some time, you will like receive a GPG error about the repository key being expired (`ED444FF07D8D0BF6`). Fortunately, this issue is quickly resolved by running the following as root:

```
wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add
```

## Install softwares

```
apt install unzip smali apktool dex2jar jadx
```

</details>

```bash
# Uncompress an APK
unzip application.apk -d ./application-unzipped/

# Disassemble DEX
baksmali d ./application-unzipped/classes.dex -o ./application-unzipped/classes.dex.out/ 2>/dev/null

# Convert .DEX files to JAVA Jar file (.class files)
d2j-dex2jar application.apk -o application.jar

# Decompile .DEX files
jadx application.apk -j $(grep -c ^processor /proc/cpuinfo) -d ./application-jadx/ > /dev/null

# Unpack the APK
apktool d application.apk -o ./application-unpacked/ 
```

## Reference

{% embed url="https://github.com/nullenc0de/reverse-apk" %}

{% embed url="https://ibotpeaches.github.io/Apktool/" %}
