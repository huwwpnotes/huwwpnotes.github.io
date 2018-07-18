---
layout: post
title: OverTheWire Bandit Walkthrough
---

## Level 0

Level 0 simply requires you to ssh in on an irregular port with a provided username and pass

`ssh bandit0@bandit.labs.overthewire.org -p2220`

## Level 1

```bsh
bandit0@bandit:~$ ls                                           
readme                                                         
bandit0@bandit:~$ cat readme                                   
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

## Level 2

```bsh
bandit1@bandit:~$ ls                                           
-
```
Using a dash as a filename is an uncommon way of writing stdin/out. To bypass add the path.
```
bandit1@bandit:~$ cat ./-                                      
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

## Level 3

```bsh
bandit2@bandit:~$ ls                                           
spaces in this filename                                        
bandit2@bandit:~$ cat spaces\ in\ this\ filename               
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

## Level 4

```bsh
bandit3@bandit:~$ ls                                           
inhere                                                         
bandit3@bandit:~$ ls -a inhere/                                
.  ..  .hidden                                                 
bandit3@bandit:~$ cat inhere/.hidden                           
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

## Level 5

```bsh
bandit4@bandit:~$ ls                                           
inhere                                                         
bandit4@bandit:~$ ls inhere                                    
-file00  -file02  -file04  -file06  -file08                    
-file01  -file03  -file05  -file07  -file09
```
We are told the password is in the only human readable file.
`strings` should do the trick.
```
bandit4@bandit:~$ strings inhere/*                             
koReBOKuIDDepwhWk7jZC0RTdopnAYKh                               
~!\                                                            
=?G0
```

## Level 6

```bsh
bandit5@bandit:~$ find -size 1033c -not -executable
./inhere/maybehere07/.file2
bandit5@bandit:~$ cat inhere/maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

## Level 7

```bsh
bandit6@bandit:~$ find / -size 33c -user bandit7 -group bandit6 2>/dev/null
/var/lib/dpkg/info/bandit7.password
```
`2>/dev/null` dumps all error messages, find from root returns a lot of permission denied
```
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

## Level 8

```bsh
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ grep millionth data.txt
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV 
```

## Level 9

```bsh
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

## Level 10

```bsh
bandit9@bandit:~$ grep -a === data.txt
```
Need -a to make grep parse binary data

## Level 11

```bsh
bandit10@bandit:~$ base64 --decode data.txt
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

## Level 12

```bsh
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```
Classic rot13

## Level 13

This is where the fun begins. First we copy the file into a working directory.

```bsh
bandit12@bandit:~$ mkdir /tmp/init7
bandit12@bandit:~$ cp data.txt /tmp/init7
bandit12@bandit:~$ cd /tmp/init7
```
Then we reverse the hexdump.
```
bandit12@bandit:/tmp/init7$ xxd -r data.txt temp
bandit12@bandit:/tmp/init7$ ls
data.txt  temp
bandit12@bandit:/tmp/init7$ file temp
temp: gzip compressed data, was "data2.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
```
gzip is picky about file extensions so rename and decompress
```bsh
bandit12@bandit:/tmp/init7$ mv temp temp.gz
bandit12@bandit:/tmp/init7$ gzip -d temp.gz
bandit12@bandit:/tmp/init7$ ls
data.txt  temp
bandit12@bandit:/tmp/init7$ file temp
temp: bzip2 compressed data, block size = 900k
```
Continue unzipping and renaming
```bsh
bandit12@bandit:/tmp/init7$ bzip2 -d temp
bzip2: Can't guess original name for temp -- using temp.out
bandit12@bandit:/tmp/init7$ file temp.out
temp.out: gzip compressed data, was "data4.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
bandit12@bandit:/tmp/init7$ mv temp.out temp.gz
bandit12@bandit:/tmp/init7$ gzip -d temp.gz
bandit12@bandit:/tmp/init7$ file temp
temp: POSIX tar archive (GNU)
```
Run a quick `<command> -h` to get the decompression syntax and continue
```bsh
bandit12@bandit:/tmp/init7$ tar -xf temp
bandit12@bandit:/tmp/init7$ ls
data.txt  data5.bin  temp
```
```bsh
bandit12@bandit:/tmp/init7$ file data5.bin
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/init7$ tar -xf data5.bin
bandit12@bandit:/tmp/init7$ ls
data.txt  data5.bin  data6.bin  temp
bandit12@bandit:/tmp/init7$ file data6.bin
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/init7$ bzip2 -d data6.bin
bzip2: Can't guess original name for data6.bin -- using data6.bin.out
bandit12@bandit:/tmp/init7$ file data6.bin.out
data6.bin.out: POSIX tar archive (GNU)
bandit12@bandit:/tmp/init7$ tar -xf data6.bin.out
bandit12@bandit:/tmp/init7$ ls
data.txt  data5.bin  data6.bin.out  data8.bin  temp
bandit12@bandit:/tmp/init7$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
bandit12@bandit:/tmp/init7$ mv data8.bin data8.gz
bandit12@bandit:/tmp/init7$ gzip -d data8.gz
bandit12@bandit:/tmp/init7$ ls
data.txt  data5.bin  data6.bin.out  data8  temp
bandit12@bandit:/tmp/init7$ file data8
data8: ASCII text
bandit12@bandit:/tmp/init7$ cat data8
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

## Level 14

```bsh
bandit13@bandit:~$ ssh bandit14@localhost -i sshkey.private
```

## Level 15

We connected via ssh so ww don't have the password yet. Fortunately all passwords are available in `/etc/bandit_pass`

```bsh
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14 | nc localhost 30000
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

## Level 15

```bsh
bandit15@bandit:~$ echo BfMYroe26WYalil77FoDi9qh59eK5xNr | openssl s_client -connect localhost:30001 -ign_eof

...

Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```
## Level 16
Determine which ports are open
```bsh
bandit16@bandit:~$ nmap -p 31000-32000 localhost

Starting Nmap 7.01 ( https://nmap.org ) at 2018-07-13 04:58 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00034s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 996 closed ports
PORT      STATE SERVICE
31046/tcp open  unknown
31518/tcp open  unknown
31691/tcp open  unknown
31790/tcp open  unknown
31960/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
```
See if any no secure ports give our answer
```bsh
bandit16@bandit:~$ echo cluFn7wTiGryunymYOu4RcffSxQluehd | nc localhost 31046
cluFn7wTiGryunymYOu4RcffSxQluehd
bandit16@bandit:~$ echo cluFn7wTiGryunymYOu4RcffSxQluehd | nc localhost 31518
bandit16@bandit:~$ echo cluFn7wTiGryunymYOu4RcffSxQluehd | nc localhost 31691
cluFn7wTiGryunymYOu4RcffSxQluehd
bandit16@bandit:~$ echo cluFn7wTiGryunymYOu4RcffSxQluehd | nc localhost 31790
bandit16@bandit:~$ echo cluFn7wTiGryunymYOu4RcffSxQluehd | nc localhost 31960
cluFn7wTiGryunymYOu4RcffSxQluehd
```
Then we try the SSL
```bsh
bandit16@bandit:~$ echo cluFn7wTiGryunymYOu4RcffSxQluehd | openssl s_client -connect localhost:31790  -ign_eof

...

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```
Save key and use however you would prefer

## Level 17

```bsh
bandit17@bandit:~$ diff passwords.new passwords.old
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> 6vcSC74ROI95NqkKaeEC2ABVMDX9TyUr
```

## Level 18

```bsh
huwwp:~$ ssh bandit18@bandit.labs.overthewire.org -p2220 "bash --norc"
cat readme
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

## Level 19

```bsh
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```

## Level 20

Use `&` to background the process

```bsh
bandit20@bandit:~$ echo GbKksEFF4yrVs6il55v6gwY5aVje5f0j | nc -lp 5000 &
[1] 18463
bandit20@bandit:~$ ./suconnect 5000
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```

## Level 21

```bsh
bandit21@bandit:~$ ls /etc/cron.d
cronjob_bandit22  cronjob_bandit23  cronjob_bandit24  popularity-contest
bandit21@bandit:~$ ls -al /etc/cron.d
total 28
drwxr-xr-x   2 root root 4096 Dec 28  2017 .
drwxr-xr-x 100 root root 4096 Mar 12 09:51 ..
-rw-r--r--   1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--   1 root root  120 Dec 28  2017 cronjob_bandit22
-rw-r--r--   1 root root  122 Dec 28  2017 cronjob_bandit23
-rw-r--r--   1 root root  120 Dec 28  2017 cronjob_bandit24
-rw-r--r--   1 root root  190 Oct 31  2017 popularity-contest
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

## Level 22

```
bandit22@bandit:~$ ls /etc/cron.d
cronjob_bandit22  cronjob_bandit23  cronjob_bandit24  popularity-contest
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit22@bandit:~$ /usr/bin/cronjob_bandit23.sh
bandit22@bandit:~$ echo "I am user bandit23" | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

## Level 23

```bsh
bandit23@bandit:~$ cat /etc/cron.d/cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        timeout -s 9 60 ./$i
        rm -f ./$i
    fi
done
```
So we need to write a bash script, put it in /var/spool/$myname and have it return us the password

```sh
!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/init723/pass24
```
Then set permissions and move to directory
```
bandit23@bandit:/tmp/init723$ chmod a+w .
bandit23@bandit:/tmp/init723$ chmod a+x initscript.sh
bandit23@bandit:/tmp/init723$ cp initscript.sh /var/spool/bandit24/
bandit23@bandit:/tmp/init723$ ls
initscript.sh  pass24
bandit23@bandit:/tmp/init723$ cat pass24
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

## Level 24

<<<<<<< HEAD
```bsh
bandit24@bandit:~$ nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode
 on a single line, separated by a space.
 ```
 We need to brute force the four digit pin. Time for a bash script.

#Work out how we filter the output

 ```bsh
 #!\bin\bash

 for i in {0000..9999}
 do
    output = echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i | nc localhost 30002
done
```
=======
```
bandit24@bandit:~$ nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 0000
Wrong! Please enter the correct pincode. Try again.
1234
Fail! You did not supply enough data. Try again.
```
So we write a bash script to generate pins
```
bandit24@bandit:/tmp/init724$ vim bruteforce.sh
#!/bin/bash

for i in {0000..9999}
do
    echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i" >> pins
done
```
Then pipe into nc and get the uniq result
```
bandit24@bandit:/tmp/init724$ cat pins | nc localhost 30002 >> result
bandit24@bandit:/tmp/init724$ uniq result
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Wrong! Please enter the correct pincode. Try again.
Correct!
The password of user bandit25 is 
```

## Bandit 26

```
bandit25@bandit:~$ ssh bandit26@localhost -i bandit26.sshkey
```
Logs you in and out immediately. So check the shell
```
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
```
So it uses more to read a file in bandit26's home directory and then exits. More is a vi controllable read so we can make our terminal less lines than the text file  and then read the password through vi shell
```
v
:r /etc/bandit_pass/bandit26
```
