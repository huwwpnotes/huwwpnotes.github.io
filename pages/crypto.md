---
layout: page
title: Cryptography
permalink: /crypto/
---

# Index

* [Encryption](#encryption)
* [Hashing](#hashing)
* [Nonces](#nonces)
* [Challenge Response](#challenge-response)
* [Windows](#windows)

---

Cryptography is the practice of securely storing and communicating information.

---

## Encryption

Encryption is the encoding of data into unintelligible ciphertext such that it can only be decoded with a key. There are two forms of encryption, symmetrical and assymetrical.

### Symmetrical Encryption

Symmetrical encryption is where the same key/cipher that is used to encode the data is the same key used to decode it. Examples are AES, DES.

### Asymmetrical Encryption

Asymmetrical encryption is where the key used to encode data is different to the one used to decode it. Sometimes it is called Public/Private Key encryption. Used in SSH, HTTPs, etc.

A piece of data signed by a public key can only be decoded with the associated private key. This is used in secure communications, PGP, etc. A piece of data signed by the private key can only be decoded with the associated public key, this is useful in ensuring a data source, for example delivering updates to software.

---

## Hashing

Hashing is the generation of a value or values from a string of text using a mathematical function. Used for ensuring data integrity and storying passwords. It is a one way function, hashing can not be reversed. Hashing produces a fixed length of output.

* The same input will always produce the same output.
* Multiple disparate inputs should not produce the same output.
* It should not be possible to go from the output to the input.
* Any modification of a given input should result in drastic change to the hash.

Messages and often hashed and signed with a private key to ensure the sender + ensure they have not been tampered with.

---

## Nonces

A none is a one time key. Usually an arbitrary number that can be used just once in a cryptographic communication. It is similar in spirit to a nonce word, hence the name. It is often a random or pseudo-random number issued in an authentication protocol to ensure that old communications cannot be reused in replay attacks.

---

## Challenge Response



---

## Windows

### NTLM

### Pass the Hash

### Kerberus

---
