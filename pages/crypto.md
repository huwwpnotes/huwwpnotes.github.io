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

A none is a one time key. Usually an arbitrary number that can be used just once in a cryptographic communication. It is often a random or pseudo-random number issued in an authentication protocol to ensure that old communications cannot be reused in replay attacks.

---

## Challenge Response

In computer security, challenge–response authentication is a family of protocols in which one party presents a question ("challenge") and another party must provide a valid answer ("response") to be authenticated.

CRA fundamentally depends on the existance of "one-way hashes". A one-way hash is a function that takes an input, and returns a "hash value". Popular one-way hash functions are MD4, MD5, SHA, and RIPE-MD.

Let's call this one-way function h(). When the client connects to the server, the server makes up a random value, X. The server sends X to the client. The client sends the server h(X+P), where P is the password and + represents concatenation. The servers computes h(X+P) as well, and checks to see if the data from the client matches the computed value. If so, the client must know P.

A practical example:

This example uses the common unix utility "md5sum", which hashes the data on stdin to a 128 bit hash, displayed as 32 hex digits.

Assume the password is "mysecretpass" and both the client and the server know this.

The client connects to the server.

The server makes up some random data, say "sldkfjdslfkjweifj".

The server sends this data to client.

The client concatenates the random data with the password, resulting in "sldkfjdslfkjweifjmysecretpass"

The client computes the MD5 hash of this value:

5>doug@saturn:/home/doug$ echo sldkfjdslfkjweifjmysecretpass | md5sum
4fab7ebffd7ef35d88494edb647bac37
5>doug@saturn:/home/doug$

The client sends "4fab7ebffd7ef35d88494edb647bac37" to the server.

The server runs the same command, and since the server (hopefully) got the same result, it lets the user in.

https://hcsw.org/reading/chalresp.txt
