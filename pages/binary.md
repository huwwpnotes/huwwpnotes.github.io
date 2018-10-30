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

1. Use a script to reproduce the crash
2. Identify the offsets
3. Identify bad characters
4. Find a useable JMP ESP
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
