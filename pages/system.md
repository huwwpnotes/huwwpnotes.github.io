---
layout: page
title: System
permalink: /system/
---

# Index
* [Enumeration](#enumeration)
* [Vulnerability Analysis](#vulnerability-anaylsis)
* [Exploitation](#exploitation)
* [Post Exploitation](#post-exploitation)

---

## Enumeration

The key to enumeration is patience.

### Passive Information Gathering

* nslookup - Plus modes for mx, etc
* the harvester - email addresses
* google
* Google Hacking Database (GHDB)
* netcraft: Web server information gathering website 
* whois: name server, registrar and contact info for domain names 
* Maltego
* recon-ng: a full-featured web reconnaissance framework written in Python #really cool 
* shodan: IOT search engine

### DNS Enumeration

* `host`: DNS lookup utility + zone transfers 
* `dnsenum`: 
* `dnsrecon`: advanced, modern, automated, cool

### Domain Wide Enumeration

* `nmap ping sweep`: for live hosts
* `nmblookup`
* `ntbscan` Netbios scan
* `onesixtyone` SNMP scan
* `snmpwalk` SNMP walk
* `snmpbulkwalk`
* `nprobe2` OS fingerprinting

### Targeted Enumeration

#### nmap

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

alternative to nmap

`unicornscan`

#### My scans proccess

Quick Scan

nmap -sC -sV -O 10.10.10.10 -oN nmap-sV-sC-O

Full TCP Scan

nmap -vv -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 -n 10.10.10.10 -oN nmap-full-tcp 

UDP Scan

nmap -sC -sV -sU 10.10.10.10 -oN nmap-full-udp

---

## Vulnerability Anaylsis

### Common Ports and How to exploit

#### 21: FTP

Banner grab for version. Several clients are directly exploitable.

`ftp`: often allows anonymous login, which depending on allowed directories can disclose information, allow us to upload a reverse shell to web root, add a schedule task, etc.

`hydra -L USER_LIST -P PASS_LIST -f -o phydra.txt -u 10.10.10.10 -s 21 ftp`

`nmap -sV -Pn -vv -21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN nmap-ftp 10.10.10.10`

#### 22: SSH

Banner grab for version. Some are directly exploitable, others allow user enumeration.

`auxiliary/scanner/ssh/ssh_enumusers`

`medusa -u root -P /usr/share/wordlists/rockyou.txt -e ns -h 10.10.10.10 - 22 -M ssh`

#### 23: Telnet

Banner grab for version, several clients are exploitable.

`hydra -l root -P /root/SecLists/Passwords/10_million_password_list_top_100.txt 192.168.1.101 telnet` : brute force with hydra

#### 25: SMTP

Server to server Simple Mail Transfer Protocol. Can not read mail, but can send and verify users. Can interact manually with nc and specific commands, or use scripts for user enum.

`nmap -script smtp-commands.nse 192.168.1.101`: to get server commands

`smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 192.168.1.103`: use command to enum users

`auxiliary/scanner/smtp/smtp_enum`

#### 53: DNS

`dnsrecon -t axfr -d 10.10.10.10`

#### 69: TFTP

FTP over UDP. Has exploitable clients, may allow anonymous access.

#### 80: HTTP

`nikto`

`gobuster`

Check /robots.txt

`VHostScan`

#### 88: Kerberos

Kerberos on 88 usually fingers a Windows Domain Controller.

`MS14-068`

#### 110/995: POP3

POP3 fetches emails from a server.

```
telnet 192.168.1.105 110
USER pelle@192.168.1.105
PASS admin

# List all emails
list

# Retrive email number 5, for example
retr 5
```

#### 111: RPCBIND

`rpcbind -p 192.168.1.101`: Get list of services running on rpc.

#### 135: MS-RPC

Microsoft's RPC Port. RPCs can be made over raw TCP as well as over SMB. `PSExec` can play with rpc. 

`nmap 192.168.0.101 --script=msrpc-enum`

`rpcclient -U "" 192.168.1.101`

`ms03_026_dcom`

`rpcclient -U \"\" 10.10.10.10`

#### 137/8?: Netbios

Allows communication between applications such as printer or other computer in Ethernet or token ring network via NETBIOS name. 
NETBIOS name is 16 digits long character assign to a computer in workgroup by WINS for name resolution of an IP address into NETBIOS name. 
To retrieve NETBIOS name: `nbstat` request over UDP/137, if possible, or check the DNS name. 

`nmblookup -A 10.10.10.10`

`smbclient //MOUNT/share -I 10.10.10.10 N`

`smbclient -L //10.10.10.10`

`enum4linux -a 10.10.10.10`

`rpcclient -U \"\" 10.10.10.10`

#### 139/445: SMB/Samba

Allows devices to perform a number of functions on each other over a (usually local) network. Usually used for file shares, sharing printers and RPC. Samba is the Linux implementation of this Windows protocol. 
SMB runs directly over TCP (port 445) or over NetBIOS (usually port 139, rarely port 137 or 138). 
The ADMIN$ share can basically be thought of as a symbolic link to the path C:\Windows. 
The IPC$ share is a little different. It does not map to the file system directly, instead providing an interface through which remote procedure calls (RPC) can be performed, as discussed below. 
Servers running SMB are often vulnerable to MS17-010 

`nmap scan for ms17-010 vuln`

`Use auxiliary/scanner/smb/smb_ms17_010`

`use exploit/windows/smb/ms17_010_eternalblue`

`smbclient -L 192.168.1.102`

`nbtscan -r 192.168.1.102`

`enum4linux -a 192.168.1.120`

`rpcclient -U "" 192.168.1.101`

`nmblookup`

`nmap -sV -Pn -vv -p 139,$port --script=smb-vuln* --script-args=unsafe=1 -oN nmap-smb-vuln 10.10.10.10`

`nmap -sV -Pn -vv -p $port --script=smb-enum-users -on nmap-smb-enum-users 10.10.10.10`

#### 143/993: IMAP

#### 161/162: SNMP

`onesixtyone` SNMP scan

`snmpwalk` SNMP walk

`snmpbulkwalk`

`snmp-check -t 192.168.1.101 -c public`

`"nmap -sV -Pn -vv -p161 --script=snmp-netstat,snmp-processes -on nmap-snmp 10.10.10.1.`

#### 389/636: Ldap

`ldapsearch -h 192.168.1.101 -p 389 -x -b "dc=mywebsite,dc=com"`

#### 443: HTTPS

Check for Heartbleed, inspect certificate.

`sslscan 192.168.101.1:443`

#### 631: Cups

Common UNIX Printing System, usually not externally open, visible internally with `netstat`
Check version, several privilege escalation vectors.

#### 1433: MsSQL

Microsoft SQL

`sqsh -S 192.168.1.101 -U sa`: connect with default service account

`scanner/mssql/mssql_login`: metasploit module to brute force login

`nmap -vv -sV -Pn -p 3306 --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -on nmap-mssql 10.10.10.10`

#### 1521: Oracle Database

`tnscmd10g`

`auxiliary/scanner/oracle/sid_brute`

https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573

#### 2049: NFS

`showmount -e 192.168.1.109`

```
mount 192.168.1.109:/ /tmp/NFS
mount -t 192.168.1.109:/ /tmp/NFS
```

#### 2100: Oracle XML DB

`ftp`: can connect with ftp

Searchsploit for exploits.
Default logins: sys:sys scott:tiger

#### 3306: MySQL

Default creds root:root
Use these to connect:

```
mysql --host=192.168.1.101 -u root -p
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost
mysql -h <Hostname> -u ""@localhost
telnet 192.168.0.101 3306

```
If you get this error, the server is set up to only allow login from 127.0.0.1, a normal security measure.

`ERROR 1130 (HY000): Host '192.168.0.101' is not allowed to connect to this MySQL server`

`cat /etc/my.cnf`: config file path

A file in the web root often has the creds for the database.

#### 3389: Remote Desktop Protocol

`rdesktop -u guest -p guest 10.11.1.5 -g 94%`

Can use nccrack or hydra to brute force

`ncrack -vv --user Administrator -P /root/passwords.txt rdp://192.168.1.101`

Ms12-020 comes up in searches but there is no POC code, don't waste time.

#### 5900: VNC

`vncviewer 192.168.1.109`

`use post/windows/gather/credentials/vnc`

`use auxiliary/scanner/vnc/vnc_login` bruteforce

`use auxiliary/scanner/vnc/vnc_none_auth`

`crowbar -b vnckey -s 10.10.10.10/32 -p IP -k PASS_FILE`

#### 8080: Common/Various

Usually a webserver, often Tomcat.

---

## Exploitation

### The Metasploit Framework

`msfconsole`

`msfcli`

### Payload Creation

`msfvenom`

`PrependMigrate=true`: migrate immediately after exploit, very useful

`veil-evasion`

`hyperion`

`unicorn`

### Payload Compilation/Execution

Compile as 32 bit executable (Linux)

`gcc -Wall -m32 -o <output> <code>`

Compile as 64 bit executable (Linux)

`gcc -Wall -m64 -o <output> <code>`

Compile windows code on Kali

`i586-mingw32msvc-gcc <source>.c -o <outfile> -lws2_32`

Run windows exploits on Kali

`wine`

### Password Attacks

#### Offline Attacks

* `crunch`:
* `pwdump/fgdump`:
* `Windows Credential Editor`
* `cewl`
* `john`: mutations

#### Online Attacks

* `hydra`
* `medusa`
* `ncrack`: can bruteforce Windows RDP

#### Password Hash Attacks

* `OpenWall`
* `HashIdentifier`
* `john`
* `Pass the Hash`
* `oclhashcat`

### Exploit Delivery

* `setoolkit`

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

#### Common Exploits for Windows Versions 
 
`MS17-010`: The reworked NSA exploits work on all unpatched versions, 32-bit and 64-bit architectures, of Windows since 2000 

`exploit/windows/smb/ms17_010_psexec`

`auxiliary/admin/smb/ms17_010_command`
 
`MS08-067`: give the most reliable shells on Windows 2003 Server and Windows XP. Also works on 2000, XP, 2003 

`exploit/windows/smb/ms08_067_netapi`

`MS06-040`: Windows 2000?

`exploit/windows/smb/ms06_040_netapi`

`MS03-026`: Window NT

`exploit/windows/dcerpc/ms03_026_dcom`

`MS05-039`: replaced by MS06-040, still viable 

`exploit/windows/smb/ms05_039_pnp`

### Maintaining Access

* upload reverse shell to web root
* add/steal SSH keys
* add user account/add to rdesktop users
* upload nc/sbd/cryptcat etc and set up reverse shell

### Transferring Files

* meterpreter upload
* Linux: many options, wget, curl, ftp, check what is installed
* Windows: TFTP (up to Windows XP by default), VBScript or Powershell, also check for FTP/Webdav/etc
* Windows: Can use debug.exe to compile a program like nc as a last resort

### Capturing Traffic

* `tcpdump`
* `tcpflow` helps logically parse pcap files
* `wireshark`
* `ettercap`
* `dsniff` find passwords, emails, usernames, etc in network traffic

### Pivoting

`ssh forwarding`

`proxy chains`

`msf proxying`

`metasploit post modules`: have tcp scans/ping sweeps, etc

`rinetd`: Port redirection 

`HTTPTunnel`

`stunnel`

### Post Exploitation Frameworks

`empire`: Powershell post exploitation framework

`powersploit`: Powershell post exploitation framework

`Nishang`: Powershell post exploitation framework


## Sources
https://xapax.gitbooks.io/security/

https://github.com/codingo/Reconnoitre
