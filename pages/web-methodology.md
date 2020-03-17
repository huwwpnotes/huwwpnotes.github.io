---
layout: page
title: Web-Methodology
permalink: /web-methodology/
---

# Index
* [Methodology](#methodology)

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
        massscan -p1-65535 -iL $TARGET_LIST --max-rate 100000 -oG $TARGET_OUTPUT (needs hostname)
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
    
3. Check for subdomain takeovers
    1. subjack
        ```
        subjack -w domain.txt -t 10 -timeout 30 -ssl -c fingerprints.json -v 3
        ```
5. Crawl websites for URLs
    1. Hakrawler
        ```
        cat domain(+gobuster results) | ~/go/bin/hakrawler -depth x -usewayback -wayback -linkfinder -plain > urls.txt
        ```
6. Check URLs for reflections in pages for potential quick wins
    1. kxss
        ```
        cat urls.txt | ./kxss
        ```
    2. XSStrike
        ```
        xsstrike -u domain.com
        ```

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
