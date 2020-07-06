---
layout: page
title: Android
permalink: /android/
---

# Index

* [Basics](#basics)

## Basics

Download the apk
```
https://apps.evozi.com/apk-downloader/
```
Use apktool to break it down
```
apktool d apk
```
Can then read through/grep for high value strings
```
grep -EHirn "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder/

find . -type f | awk -F. '!a[$NF]++{print $NF} //show all file extensions in apk

grep -rE "https?://.*domain.*" . //find urls referencing domain
```
Can use dex2jar to convert to apk to jar
```
https://github.com/pxb1988/dex2jar
d2j-dex2jar.sh -f ~/path/to/apk_to_decompile.apk
```
And then jd-gui to read as java code (nicer than apktool smali files which are java bytecode, more low level)
```
https://tools.kali.org/reverse-engineering/jd-gui
```
