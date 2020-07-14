---
layout: page
title: Android
permalink: /android/
---

# Index

* [Basics](#basics)
* [Search Patterns](#search-patterns)
* [Insecure Storage](#insecure-storage)
* [Insecure Logging](#insecure-logging)
* [Exported Activities](#exported-activities)
* [Exported Content Providers](#exported-content-providers)
* [Exported Receivers](#exported-receivers)
* [Exported Services](#exported-services)
* [Deeplinks](#deeplinks)


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
Use jadx to decompile to readable java code
```
https://github.com/skylot/jadx
mkdir decompile
jadx company.apk -d decompile
```
Check if Application backups are enabled
```
cat AndroidManifest.xml | "grep android:allowBackup"
```

## Search Patterns
Grep for high value strings
```
grep -EHirn "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into"
```
Show all file extensions in apk
```
find . -type f | awk -F. '!a[$NF]++{print $NF} 
```
Find urls referencing domain
```
grep -rE "https?://.*domain.*" .
```
Find byte strings (often used to encode stuff)
```
grep -ir "final byte\[\]" | grep "\}"
```
Search to temporary file creation
```
grep -ir "file.Create"
```
Search for insecure external storage usage
```
grep -ir "ExternalStorage"
```
Search for SQL Injection points
```
grep -ir "rawquery"
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

## Exported Activities
Exported activities can be called by other apps on the phone.
```
Check the AndroidManifest.xml
cat AndroidManifest.xml | grep "activity" | grep "exported=\"true\""

run through adb with
adb shell am start -n com.packagename/.x.x.x.ActivityName
```
We want to see if the activity accepts any user input and if we can misuse it.
Inspect the source code of the activity and look for calls to getIntent()
```
string x_value = getIntent().getStringExtra(x_key); //store into x_value the string after x_key in the intent

run through adb with
shell am start -n com.packagename/.x.ActivityName -e x_key "INJECT_HERE"

https://www.youtube.com/watch?v=ZUikTuoCP_M
```

## Exported Content Providers
Content providers are used to share app data with other applications, which is normally stored inside a database or file.
Check if any values are under user contol.
```
Check the AndroidManifest.xml
cat AndroidManifest.xml | grep "provider"

run through adb with
adb shell content –query –uri content://com.PackageName.ProviderName/PATH
```

## Exported Receivers
Receivers listen for broadcasts and perform action based upon intents received.
```
Check the AndroidManifest.xml
cat AndroidManifest.xml | grep "receiver" | grep exported=\"true\"

run through adb with
adb shell am broadcast -a *android:name* -n com.packagename/x.BroadcastName
```

## Exported Services
```
Check the AndroidManifest.xml
cat AndroidManifest.xml | grep "service" | grep exported=\"true\"

run through adb with
adb shell service call SERVICENAME args 
```

## Deeplinks

A deep link is an intent filter system that allows users to directly enter a specific activity in an Android app.
At minimum a deeplink must have a "data" tag with an android:scheme attribute.
Test for user controlled values.
```
cat AndroidManifest.xml | grep "data:scheme"
  
run through adb with
adb shell start -W -a android.intent.action.VIEW -d "URI" package
```
