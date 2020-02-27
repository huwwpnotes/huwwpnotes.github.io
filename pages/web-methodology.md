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
        `amass enum -active -d domain.com > domain.txt`
    2. subbrute for brute force
        `./subbrute.py domain.txt > domainbrute.txt`
    3. Subdomain wildcard detection https://gist.github.com/003random/dffed7fbad7117796fe6197422a91648
    4. FDNS Dataset Query
        `zcat fdns.json.gz | grep -F '.example.com"'`
    5. Use massdns to check if actually live
        ```
        cat domains.txt | ./bin/massdns -r lists/resolvers.txt -t A -o S -w results.txt
        ```
3. Check for subdomain takeovers
    1. subjack
        `subjack -w domain.txt -t 10 -timeout 30 -ssl -c fingerprints.json -v 3`
    2.
     ```
    From massdns results get a list of CNAMEs
    cat results.txt | grep CNAME | cut --complement -d ' ' -f 2
    ```
4. Screenshot at this point and probably after directory bruteforcing (aquatone, eyewitness, webscreenshot)
5. For each subdomain perform directory brute forcing
    1. Gobuster
6. Test each "site" for information + low hanging fruit
    1. nmap
    2. Using components with Known Vulnerabilities
    3. Security misconfiguration (open buckets, no auth control)
7. Identify points of interaction
    1. Burp
    2. Parameter discovery: https://github.com/s0md3v/Arjun https://github.com/maK-/parameth
8. Test each point of interaction for vulnerabilities
    1. Injection
    2. XSS
    3. CSRF
    4. SSRF
    5. File Inclusion
9. Test for other issues
    1. Access control failures
    2. Logic failures
    3. Cookies/JWT
