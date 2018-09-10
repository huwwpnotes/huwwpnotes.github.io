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

## SMB

`nmap scripts` especially beyond the default one

`enum4linux -a 192.168.1.1`

`smbclient`

`nmblookup`

## Others

`ntbscan` Netbios scan

`onesixtyone` SNMP scan

`snmpwalk` SNMP walk

`snmpbulkwalk`

`nprobe2` OS fingerprinting

`rpclient`

`unicornscan` alternative to nmap

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

`unicorn`

## Password Attacks

`john`

## Exploit Delivery

---

## Post Exploitation

### Privilege Escalation

#### Linux

Atacking the kernel is the easiest route to Linux priviledge escalation, it is also the fast to test.

We start with determining our version/checking for exploits.

`uname -a` : Get the linux version

`cat /etc/*release`: Get the distro version

`searchsploit` against the kernel/distro for exploits

This process can be automated (accuracy may vary) with

`UnixPrivEsc.sh`

If we can not exploit the kernel for priv esc then we manually investigate potential misconfigurations.

Try to work from `/dev/shm`, as it is stored in memory

`sudo -l`: shows us all the programs we have sudo rights to (requires current user password)

`find / -perm -4000 2>/dev/null`: finds all suid executables

`LinEnum.sh`: comprehensive enumeration script

`LinuxPrivChecker.py`: haven't used but well reviewed

If nothing stands out then we go through g0tm1lk's guide.

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

If all the above fails we are left with password attacks.

#### Windows

First we start with trying to exploit the OS.

`systeminfo`: Gives us OS/Version/Installed updates. We can google these for MS# or use the below scripts to try determine which ones to try. If we are using XP SP0 or SP1 there is a simple universal service exploit we can use to get system.

`Windows-Exploit-Suggester`: Takes the output of systeminfo and tells us if there are any viable exploits

`sherlock.ps1`: Looks for missing patches for priv esc vectors, requires powershell

`msfconsole local_exploit_suggester`: Run against a meterpreter sessions for suggested exploits

`meterpreter getsystem`: a meterpreter session can attempt to upgrade itself

`windows-privesc-check`: General privesc scan script

`powerup.ps1`: General privesc powershell script

https://github.com/SecWiki/windows-kernel-exploits : Exploits with examples/precompiled

If none of the above work then we need to attempt priv esc manually.

Follow the fuzzysecurity guide
http://www.fuzzysecurity.com/tutorials/16.html

`SEDebugPriviledge` if a user has this we can exploit for admin

If all the above fails we are left with password attacks

`pwdump\fgdump`: Windows NT/2000/XP/2003 NTLM and LanMan Password Grabber. I think works up to Windows 10

`windows credential editor`: Win XP-7, gets NTLM hashes, Kerberos tickets and plaintext passwords. Requires local admin

While not priv esc, we can get current user credentials hash snarf via samba/http metasploit modules

`mimikatz`: Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory, pass-the-hash, pass-the-ticket, build Golden tickets, play with certificates or private keys. Most functions require admin. Win XP-10

### Maintaining Access

* upload reverse shell to web root
* add/steal SSH keys
* add user account/add to rdesktop users
* upload nc/sbd/cryptcat etc and set up reverse shell

#### Windows



#### Linux

### Pivoting

`ssh forwarding`

`proxy chains`

`msf proxying`

### Post Exploitation Frameworks

`empire`: Powershell post exploitation framework

`powersploit`: Powershell post exploitation framework

`Nishang`: Powershell post exploitation framework

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
* `tcpflow` helps logically parse pcap files
* `wireshark`
* `ettercap`
* `dsniff` find passwords, emails, usernames, etc in network traffic