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
Or pull it from your phone over ADB
```
adb shell pm list packages
adb shell pm path com.example.someapp
adb pull /data/app/com.example.someapp-2.apk
```
Use apktool to break it down
```
apktool d apk
```
Check /res/raw, /assets/, AndroidManifest.xml and /res/values/strings.xml for quick wins. Check *.firebase.com/.json
Can then read through/grep for high value strings
```
grep -EHirn "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder/

Show all file extensions in apk
find . -type f | awk -F. '!a[$NF]++{print $NF} 

//find urls referencing domain
grep -rE "https?://.*domain.*" .

```
Use jadx to decompile to readable java code
```
https://github.com/skylot/jadx
mkdir decompile
jadx company.apk -d decompile
```
Find byte strings (often used to encode stuff)
```
grep -ir "final byte\[\]" | grep "\}"
```
