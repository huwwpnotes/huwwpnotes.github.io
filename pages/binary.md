---
layout: page
title: Binary
permalink: /binary/
---

# Index

* [Programming](#programming)
* [Assembly](#assembly)
* [Reversing](#reversing)
* [Buffer Overflows](#overflows)

## Programming

### Pointers

`&` address of operator = the actual data in the pointer variable

`*` dereference operator = the data in the address the pointer is pointing to

```c
#include <stdio.h>

int main() {
    int int_var = 5;
    int *int_ptr;

    int_ptr = &int_var; //put the address of int_var into int_ptr;

    printf("int_ptr = 0x%08x\n", int_ptr);
    printf("&int_ptr = 0x%08x\n", &int_ptr);
    printf("*int_ptr = 0x%08x\n\n", *int_ptr);

    printf("int_var is located at 0x%08x and contains %d\n", &int_var, int_var);
    printf("int_ptr is located at 0x%08x and contains 0x%08x, and points to %d\n\n", &int_ptr, int_ptr, *int_ptr);

}
```
Gives
```
int_ptr = 0xcd26658c
&int_ptr = 0xcd266590
*int_ptr = 0x00000005

int_var is located at 0xcd26658c and contains 5
int_ptr is located at 0xcd266590 and contains 0xcd26658c, and points to 5
```

When the unary operators are used with pointers, the address-of operator
can be thought of as moving backward, while the dereference operator
moves forward in the direction the pointer is pointing.

### Memory Segments

![Memory Segments]({{ site.url }}/assets/segments.JPG)


>In C, as in other compiled languages, the compiled code goes into the text segment, while the variables reside in the remaining segments. Exactly which memory segment a variable will be stored in depends on how the variable is
defined. Variables that are defined outside of any functions are considered to be global. The static keyword can also be prepended to any variable declaration to make the variable static. If static or global variables are initialized with data, they are stored in the data memory segment; otherwise, these variables are put in the bss memory segment. Memory on the heap memory segment must first be allocated using a memory allocation function called malloc(). Usually, pointers are used to reference memory on the heap. Finally, the remaining function variables are stored in the stack memory segment. Since the stack can contain many different stack frames, stack variables can maintain uniqueness within different functional contexts.

`From 'Hacking: The Art of Exploitation'`

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

`Examine` can also be used to return the instruction at an address, not just the value.

`(gdb) x/i $eip` examine the next instruction at $eip

`(gdb) x/3i $eip` examine the next three instructions

`(gdb) nexti` read EIP, execute it and advance EIP to the next instruction

`(gdb) x/6cb 0x8048484` read 6 bytes as ASCII chars

`(gdb) x/s 0x8048484` read as an ASCII string

`(gdb) cont` continue from a breakpoint

`(gdb) bt` backtrace, show the stack

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