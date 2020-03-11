---
layout: page
title: Web-Methodology
permalink: /web-methodology/
---

# Index
* [Methodology](#methodology)

---

## Methodology

1. Start up burp & cherrytree, set to spider mode while we explore.
2. Begin subdomain enumeration
    1. Amass
        ```
        amass enum -active -d domain.com > domain.txt
        ```
    2. subbrute for brute force
        ```
        ./subbrute.py domain.com > domainbrute.txt
        ```
    3. Subdomain wildcard detection https://gist.github.com/003random/dffed7fbad7117796fe6197422a91648
    4. FDNS Dataset Query
        ```
        zcat fdns.json.gz | grep -F '.example.com"'
        ```
    5. Use massdns to check if actually live
        ```
        cat domains.txt | ./bin/massdns -r lists/resolvers.txt -t A -o S -w results.txt
        
        For all live subdomains:
        cat results.txt | cut -d ' ' -f 1
        
        From massdns results get a list of CNAMEs
        cat results.txt | grep CNAME | cut --complement -d ' ' -f 2
        ```
    6. Check for live webservers on subdomains
        ```
        cat recon/example/domains.txt | httprobe
        ```
3. Check for subdomain takeovers
    1. subjack
        ```
        subjack -w domain.txt -t 10 -timeout 30 -ssl -c fingerprints.json -v 3
        ```
3. If allowed perform generic scanning
    1. Gobuster
    2. Nikto
5. Crawl websites for URLs
    1. Hakrawler
        ```
        cat domain(+gobuster results) | ~/go/bin/hakrawler -depth x -usewayback -wayback -linkfinder -plain > urls.txt
        ```
6. Check URLs for reflections in pages for potentials quick wins
    1. kxss
        ```
        cat urls.txt | ./kxss
        ```


https://github.com/s0md3v/Arjun
https://github.com/maK-/parameth
