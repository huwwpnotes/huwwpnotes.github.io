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
    1. Amass/Sublister/crtsh 
        `amass enum -d domain.com > domain.txt`
    2. massdns/gobuster for brute force
3. Check for subdomain takeovers
    1. subjack
        `subjack -w domain.txt -t 10 -timeout 30 -ssl -c fingerprints.json -v 3`
3. For each subdomain perform directory brute forcing
    1. Gobuster
4. Test each "site" for information + low hanging fruit
    1. nmap
    2. Using components with Known Vulnerabilities
    3. Security misconfiguration (open buckets, no auth control)
5. Identify points of interaction
    1. Burp
6. Test each point of interaction for vulnerabilities
    1. Injection
    2. XSS
    3. CSRF
    4. SSRF
    5. File Inclusion
7. Test for other issues
    1. Access control failures
    2. Logic failures
    3. Cookies/JWT
