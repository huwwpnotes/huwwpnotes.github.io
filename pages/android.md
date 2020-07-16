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
If the application is React Native then code will be stored in
```
index.android.bundle

If index.android.bundle.map is present you can take advantage of this by creating a file named index.html in the same directory with the following within it:
<script src="index.android.bundle"></script>
Save this file and then open it in Google Chrome. Open up the Developer Toolbar (Command+Option+J for OS X or Control+Shift+J for Windows), and click on “Sources”.
```

## Search Patterns
Check if any keys in build config files
```
find . -name "*BuildConfig*" -exec cat {} \;
```
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
Grep for AWS Keys
```
grep -RP '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])' *
```
Grep for deeplinks
```
grep -ir "://"
```
Grep for suspicious methods
```
shouldOverrideUrlLoading, shouldInterceptRequest, onDownloadStart, FirebaseDatabase.getInstance(), setJavaScriptEnabled(true).
```
Token Regexes
```
{
	"Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
	"SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
	"SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
	"PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
	"Amazon AWS Access Key ID": "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
	"Amazon AWS S3 Bucket": [
		"[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
		"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
		"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
		"//s3\\.amazonaws\\.com/[a-z0-9._-]+",
		"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
		"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	],
	"AWS API Key": "AKIA[0-9A-Z]{16}",
	"Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
	"Facebook OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
	"Firebase": "[a-z0-9.-]+\\.firebaseio\\.com",
	"GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
	"Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
	"Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
	"Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
	"Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
	"Google (GCP) Service-account": "\"type\": \"service_account\"",
	"Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
	"Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	"IP Address": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
	"LinkFinder": "(?:\"|')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^\"'\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:\/|\\.\\.\/|\\.\/)[^\"'><,;| *()(%%$^\/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|)))(?:\"|')",
	"MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
	"Mailgun API Key": "key-[0-9a-zA-Z]{32}",
	"Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
	"PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
	"Picatic API Key": "sk_live_[0-9a-z]{32}",
	"Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	"Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
	"Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
	"Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
	"Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
	"Twilio API Key": "SK[0-9a-fA-F]{32}",
	"Twitter Access Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
	"Twitter OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
}
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
