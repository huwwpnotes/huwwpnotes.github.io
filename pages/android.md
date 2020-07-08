---
layout: page
title: Android
permalink: /android/
---

# Index

* [Basics](#basics)
* [Insecure Storage](#insecure-storage)
* [Insecure Logging](#insecure-logging)
* [Exported Activities](#exported-activities)
* [Exported Content Providers](#exported-content-providers)


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
Check if Application backups are enabled
```
cat AndroidManifest.xml | "grep android:allowBackup"
```

## Insecure Storage

Install the app on a real or emulated device. Login to accounts, associate with socials etc.
Then open a shell on the device with adb and try to find those creds, often in databases.
```
adb shell phonename
cd /data/data #path for most package data
ls
...
```
Also worth checking for external storage (on the SD card/non-data folder)
```
grep -ir "External"
```

## Insecure Logging
During runtime run logcat and check for data being logged
```
adb logcat
```

## Exported Activitiees
This element sets whether the activity can be launched by components of other application.
The default value depends on whether the activity contains intent filters. The absence of any filters means that the activity can be invoked only by specifying its exact class name. 
Check if any values are under user contol.
```
Check the AndroidManifest.xml
cat AndroidManifest.xml | grep "activity" | grep "exported=\"true\""
```

## Exported Content Providers
Content providers are used to share app data with other applications, which is normally stored inside a database or file.
Check if any values are under user contol.
```
Check the AndroidManifest.xml
cat AndroidManifest.xml | grep "provider"
```
