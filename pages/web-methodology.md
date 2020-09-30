---
layout: page
title: Web-Methodology
permalink: /web-methodology/
---

# Index
* [Methodology](#methodology)
* [Access Control](#access-control)
* [SSRF](#ssrf)
* [Header Manipulation](#header-manipulation)
* [Open Redirect](#open-redirect)
* [DOM Manipulation](#dom-manipulation)
* [Oneliners](#oneliners)

---

Todo:
- Redo 5 onwards
- Uplift Wordlists
- Looks at frameworks from https://www.youtube.com/watch?v=p4JgIu1mceI 1:29 onwards

## Methodology

1. Start up burp & cherrytree, set to spider mode while we explore. Maybe look into xmind mapping.
2. Begin automated subdomain enumeration
    1. Subdomain Scraping
        ```
        amass enum -active -d domain.com > amass.txt
        ```
    2. FDNS Dataset Query
        ```
        zcat fdns.json.gz | grep -F '.example.com"' > fqdns.txt
        cat fqdns.txt | grep -F '.example.com"' | jq -r .name | sort | uniq > fqdns-cleaned.txt #might get cnames on wrong side
        
        Web service offering the same dataset, might be less accurate but fast
        curl 'https://tls.bufferover.run/dns?q=.magisto.com 2>/dev/null | jq .Results > bufferover.txt
        ```
    3. Subdomain Brute Forcinng
        ```
        shuffledns
        
        shuffledns -d domain.com -w /opt/all-wordlist/all.txt -r /opt/massdns/lists/resolvers.txt > brute.txt
               
        Wordlists are very important here
        Either jhaddix all or tomnomnom custom style
        ```
    4. Github
       ```
       github-subdomains.py -d domain.com > github-sub.txt
       ```
    4. Resolving Check
       ```
       Combine the three above, check what resolves and use as master list
       
       shuffledns -d example.com -list combined-list.txt -r /opt/massdns/lists/resolvers.txt > master.txt
       ```
    5. Chaos
       ```
       https://chaos.projectdiscovery.io/#/
       ```
3. Manual subdomain enumeration
    1. Builtwith
       ```
       Builtwith relationships tabs shows websites running same analytic tracking codes
       ```
    2. Shodan
       ```
       search TLD
       https://github.com/incogbyte/shosubgo
       ```
    3. Link Discovery
       ```
       Do one of:
       1. Burp: Turn off active scanner, walk the site, spider all hosts discovered, can do recursively (over and over again). Export with analyze target
       2. GoSpider
       3. Hakrawler
       ```
    4. Javascript Link Discovery
       ```
       1. Subdomainizer
       2. Subscraper
       ```
    5. Validate with shuffledns what is resolving from manual checks

3. Service Identification
    1. Massdns to get IP addresses
       ```
       massdns -r /opt/massdns/lists/resolvers.txt -t A -q -o S master.txt > massdns.txt
       
       Get IP Addresses
       
       cat massdns.txt | grep "A " | cut -d " " -f 3 > ips.txt # Does this miss some cnames though?
       ```
    2. Massscan to see what is running on hosts
        ```
        massscan -p1-65535 -iL ips.txt --max-rate 10000 -oN masscan.txt
        ```
    3. Brutespray for weak passwords on remote admin protocols
        ```
        brutespray.py
        ```
    4. Eyewitness for visual identification and/or httpprobe
        ```
        Eyewitness.py
        httprobe
        ```
 
4. Other Enumeration/Wide Recons
    1. Github Dorks
        ```
        Gdorklinks.sh https://gist.githubusercontent.com/jhaddix/1fb7ab2409ab579178d2a79959909b33/raw/e9fea4c0f6982546d90d241bc3e19627a7083e5e/Gdorklinks.sh
        ```
    2. Subdomain Takeover
        ```
        subjack -w domain.txt -t 10 -timeout 30 -ssl -c fingerprints.json -v 3
        SubOver
        Nuclei
        ```
    3. AWS S3 Bucket Testing
        ```
        s3scanner/Nuclei
        ```
        
5. Application Testing
    1. Wayback enumeration
        ```
        waybackurls
        ```
    2. Platform Identification & CVE Searching for Webapps
        ```
        Retire.js
        Wappalyzer
        Builtwith
        Burp Vulners Scanner
        ```
    3. Javascript Examination
        ```
        Linkfinder (probably better than JSParser)
        ```
    4. Content Discovery 
        ```
        Gobuster
        Robots Disallowed
        Burp Content Discovery
        iis_shortname_scanner
        ```

## Access Control

To test access controls including IDORs

```
1. Create two accounts.
2. Capture the cookies from account 2 and enter into Autorize
3. Log into the app as account 1 and try everything, Autorize will replay all requests as account 2
```

To test access controls not based upon cookies (URL parameters, UUIDs etc)

```
1. AutoRepeater, match string in proxied requests and replay with alternate values
```

## SSRF

Anytime you find a URL/Header/Post data in an app that references another application/server/site, try to change it to hit a URL you control. Often need to bypass blacklists/whitelists. May need to add requests manipulating headers (e.g. X-Forwarded-For).

https://portswigger.net/web-security/ssrf

## Header Manipulation

Sometimes messings with certain headers can modify the behaviour of an application. Can allow access to internal apps, bypass access controls, cause XSS, etc.
- Host: 127.0.0.1
- X-Forwarded-For: 127.0.0.1
- Referer: 127.0.0.1
- X-Originating-IP: 127.0.0.1
- Remote-IP: 127.0.0.1
- Remote-Addr: 127.0.0.1
- Client-IP: 127.0.0.1
- Host: 127.0.0.1
- Forwarded-Host: 127.0.0.1

While bruteforcing URLs can set "Host: Localhost" for potentially more access

## Open Redirect

Walk the page with burpsuite, interact wherever you can. Once you are done Analyze the target, look for potential parameters (GET and POST) like:

* url=
* redirect=
* next=
* to=
* goto=
* etc

Send these requests to burp intruder, set the payload for just these parameters and use an open redirect wordlist.

## DOM Manipulation

### Sources
* document.url
* document.documenturi
* location
* location.href
* location.search
* location.pathname
* location.hash
* document.referrer
* window.name

### Sinks
* eval
* setTimeOut
* setInterval
* function
* document.write
* document.writeIn
* innerhtml
* outerhtml
* location
* location.href
* location.replace
* location.assign

## Oneliners

Bash loop
```
cat paths.txt | while read line || [ -n "$line" ]; do ffuf -u http://domain.com/$line/FUZZ -w /opt/SecLists/Discovery/Web-Content/big.txt -e .html; done
```
Curl status codes, response sizes, only single threaded
```
cat urls.txt | while read LINE; do curl -o /dev/null --silent --head --write-out "%{http_code}; $LINE\n" "$LINE"; done > statuses.txt
```
Parallelised check status codes
```
cat urls.txt | xargs -n1 -P 10 curl -o /dev/null --silent --head --write-out  ' %{http_code} %{url_effective} \n' >> statuscodes.txt
```
Discover parameters
```
python3 /opt/arjun.py -u https://api.example.com/endpoint --get
```
Find XSS
```
echo https://www.domain.com/ | hakrawler -scope subs -depth 3 -plain -linkfinder | /opt/kxss/kxss
```
Get all first level subdomains from list of all subdomains
```
cat master.txt | awk -F "." '{print $(NF-2)"."$(NF-1)"."$NF}' | sort -u
```
ffuf recursion
```
ffuf -u https://test.com/FUZZ -w ./wordlist -recursion
https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html
```
Find lines in file 1 that aren't in file 2
```
comm -23 <(sort -u file1.txt) <(sort -u file2.txt)
```

## Add the rest of these https://portswigger.net/web-security/all-materials
