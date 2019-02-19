---
layout: page
title: Windows
permalink: /windows/
---

# Index

* [Overview](#overview)
* [Acquiring Windows Hashes](#acquiring-windows-hashes)

## Overview

When a local user account is created the password is stored in the Security Accounts Manager (SAM) database.

When an AD account is created the password is stored in Ntds.dit, the main AD Database. The password hashes are encrypted using a key
stored in the SYSTEM registry hive.

When a user logs into a Windows machine their password is stored in the Local Security Authority Subsystem Service (LSASS) as a NTLM hash.
LSASS loads the SAM service into it's process. Then when a user tries to access a network resource (for example a smb share)
they are issued a challenge, LSASS responds with a concatenated challenge + response which the network resource then confirms
as correct with the domain controller.

As the network resources only request the hashes and not the passwords, this opens up the possibility of pass the hash attacks.

## Acquiring Windows Hashes

Assuming we have a shell on a Windows machine, we can acquire the NTLM hashes. A non-privileged account can generally only be used to
reveal it's own hashes, while a Local Admin account should be able to dump the hashes of all accounts that have logged onto the machine.

A non privileged account can't access the SAM file to see the hashes, but it can make a connection to a SMB server we control and in doing
so send us its hash.
