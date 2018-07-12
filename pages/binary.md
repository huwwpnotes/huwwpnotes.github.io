---
layout: page
title: Binary
permalink: /binary/
---

# Index

* [Reversing](#reversing)
* [Buffer Overflows](#overflows)

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

### GDB

The GDB (GNU Debugger), best for dynamic analysis. Starts in an interactive shell.

`gdb` or `gdb <program>`

Set the disassembly syntax to Intel

`set disassembly-flavor intel`

File to choose file to work on

`file <program>`

Disassemble a function

`disassemble main`

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

## Buffer Overflows

Further reading
* http://insecure.org/stf/smashstack.html

### Off By One

### Printf Errors

### Number Signing