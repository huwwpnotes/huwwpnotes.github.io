---
layout: page
title: Web-Methodology
permalink: /web-methodology/
---

# Index
* [Methodology](#methodology)
* [DOM XSS](#dom)

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
    4. Resolving Check
       ```
       Combine the three above, check what resolves and use as master list
       
       shuffledns -d example.com -list combined-list.txt -r /opt/massdns/lists/resolvers.txt > master.txt
3. Manual subdomain enumeration
    1. Builtwith
       ```
       Builtwith relationships tabs shows websites running same analytic tracking codes
       ```
    2. Github Subdomain Discovery
       ```
       github-subdomains.py -d domain.com > github-sub.txt
       ```    
    3. Google Dorks
       ```
       "® 2020 Businessname" inurl:businessname
       
       Copyright/privacy text etc
       
       site:business.com -www.business.com -obvious.business.com -etc
       ```
    4. Shodan
       ```
       search TLD
       https://github.com/incogbyte/shosubgo
       ```
    5. Link Discovery
       ```
       Do one of:
       1. Burp: Turn off active scanner, walk the site, spider all hosts discovered, can do recursively (over and over again). Export with analyze target
       2. GoSpider
       3. Hakrawler
       ```
    6. Javascript Link Discovery
       ```
       1. Subdomainizer
       2. Subscraper
       ```
    7. Validate with shuffledns what is resolving from manual checks

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
        ZAP Ajax Spider
        Linkfinder (probably better than JSParser)
        ```
    4. Content Discovery 
        ```
        Gobuster
        Robots Disallowed
        Burp Content Discovery
        ```
    5. Parameter Bruting
        ```
        parameth
        ```
    
7. Crawl websites for URLs
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
       
8. Directory brute force
    1. Gobuster

9. Burp Suite
    1. Set up a proxy/spider/audit, have manually active while you test the site
        ```
        - Change crawl to not submit forms/attempt to register users
        - Change crawl max depth to 5
        - Audit can easily get you IP banned
        ```
    
10. Manual testing
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

## Open Redirect

Walk the page with burpsuite, interact wherever you can. Once you are done Analyze the target, look for potential parameters (GET and POST) like:

* url=
* redirect=
* next=
* to=
* goto=
* etc

Send these requests to burp intruder, set the payload for just these parameters and use an open redirect wordlist.


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
