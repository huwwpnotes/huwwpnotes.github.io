---
layout: page
title: System
permalink: /system/
---

# Index
* [Enumeration](#enumeration)
    * [nmap](#nmap)
    * [Nessus](#nessus)
    * [Metasploit Scanner Modules](metasploit-scanner-modules)
* [Vulnerability Analysis](#vulnerability-anaylsis)
* [Exploitation](#exploitation)
    * [The Metasploit Framework](#the-metasploit-framework)
    * [Payload Creation](#payload-creation)
    * [Password Attacks](#password-attacks)
    * [Exploit Delivery](#exploit-delivery)
* [Post Exploitation](#post-Exploitation)
    * [Enumeration](#enumeration)
    * [Maintaining Access](#maintaining-access)
    * [Privilege Escalation](#privilege-escalation)
* [Pentesting Methodology](#pentesting-methodology)
* [Information Gathering](#information-gathering)
* [Capturing Traffic](#capturing-traffic)

---

## Enumeration

The key to enumeration is patience.

### nmap

TCP SYN port scan (default)

`nmap 192.168.1.1 -sS` 

TCP connect port scan

`nmap 192.168.1.1 -sT`

UDP port scan

`nmap 192.168.1.1 -sU`

TCP ACK port scan

`nmap 192.168.1.1 -sA`

Version scan

`nmap 192.168.1.1 -sV`

Scripts scan

`nmap 192.168.1.1 -sC`

OS Detection

`nmap 192.168.1.1 -O`

Output in all three forms

`nmap 192.168.1.1 -oA out.file`

Control speed/aggressiveness

`nmap 192.168.1.1 -T<0-5> -min-rate <number>`

Version scan, all ports, run scripts, grab OS information and output to all formats

`nmamp -p- -A 192.168.1.1 -oA out.file`

## Nessus

Nessus Home is a vulnerability scanner.

## Metasploit Scanner Modules

Metasploit has modules for scanning specific potential vulnerablities.

You can also use the `check` function on some exploit modules to test if vulnerable without actually exploiting.

---


## Vulnerability Anaylsis

Take the results from enumeration and determine if there are any potential vulnerabilities.

`searchsploit`

`google`

---

## Exploitation

### The Metasploit Framework

`msfconsole`

`msfcli`

### Payload Creation

`msfvenom`

`veil-evasion`

`hyperion`

## Password Attacks

`john`

## Exploit Delivery

---

## Post Exploitation

### Enumeration

`LinEnum.sh`

`psexec`

`mimikatz`

### Maintaining Access

### Privilege Escalation

---

## Pentesting Methodology

http://www.pentest-standard.org/index.php/Main_Page

---

## Information Gathering

* nslookup - Plus modes for mx, etc
* the harvester - email addresses
* google/whois
* Maltego

---

## Capturing Traffic

* `tcpdump`
* `wireshark`
* `ettercap`