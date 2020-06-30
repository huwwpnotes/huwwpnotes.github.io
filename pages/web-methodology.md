---
layout: page
title: Web-Methodology
permalink: /web-methodology/
---

# Index
* [Methodology](#methodology)
* [DOM XSS](#dom)

---

## Methodology

1. Start up burp & cherrytree, set to spider mode while we explore. Maybe look into xmind mapping.
2. Begin subdomain enumeration
    1. Amass
        ```
        amass enum -active -d domain.com > domain.txt
        ```
    2. FDNS Dataset Query
        ```
        zcat fdns.json.gz | grep -F '.example.com"'
        ```
    3. MassDNS
        ```
        ./subbrute.py domain.com  | ./bin/massdns -r lists/resolvers.txt -t A -o S -w results.txt
        
        For all live subdomains:
        cat results.txt | cut -d ' ' -f 1
        
        From massdns results get a list of CNAMEs
        cat results.txt | grep CNAME | cut --complement -d ' ' -f 2
        ```
    4. Massscan to see what is running on hosts
        ```
        massscan -p1-65535 -iL $TARGET_LIST --max-rate 10000 -oG $TARGET_OUTPUT (needs IP not hostname)
        ```
    5. Brutespray for weak passwords on remote admin protocols
        ```
        brutespray.py
        ```
    6. Eyewitness for visual identification and/or httpprobe
        ```
        Eyewitness.py
        httprobe
        ```
    7. Wayback enumeration
        ```
        waybackurls
        ```
    8. Platform Identification & CVE Searching for Webapps
        ```
        Retire.js
        Wappalyzer
        Builtwith
        Burp Vulners Scanner
        ```
    9. Javascript Examination
        ```
        ZAP Ajax Spider
        Linkfinder (probably better than JSParser)
        ```
    10. Content Discovery 
        ```
        Gobuster
        Robots Disallowed
        Burp Content Discovery
        ```
    11. Parameter Bruting
        ```
        parameth
        ```
    
3. Check for misconfigurations
    1. subjack
        ```
        subjack -w domain.txt -t 10 -timeout 30 -ssl -c fingerprints.json -v 3
        ```
    2. AWS
       ```
       s3scanner
       ```
5. Crawl websites for URLs
    1. Hakrawler
        ```
        cat domain(+gobuster results) | ~/go/bin/hakrawler -depth x -usewayback -wayback -linkfinder -plain > urls.txt
        ```
    2. Validate if urls in txt file are live
        ```
        cat file | xargs -n 1 -P 50 curl --head -w "%{http_code} %{url_effective}\n" -s -o /dev/null -k
        fails on apostrophe
        cat file | grep -v \' | xargs ...
        ```
       
7. Directory brute force
    1. Gobuster

8. Burp Suite
    1. Set up a proxy/spider/audit, have manually active while you test the site
        ```
        - Change crawl to not submit forms/attempt to register users
        - Change crawl max depth to 5
        - Audit can easily get you IP banned
        ```
    
9. Manual testing
    1. Client Side Controls
        ```
        - Register a user, see if can include xss, null bytes, escape characters in name, address, etc
        - Try register the same user with null byte, see if you can overtake
        ```
    2. Access Controls
        ```
        - Create a user map what they have access to inside authentication
        - Try to access without being logged in
        - Create a second user and try to access the first users stuff
        ```
    3. IDOR
    4. Upload Functions
    

## DOM XSS

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

https://github.com/s0md3v/Arjun
https://github.com/maK-/parameth
