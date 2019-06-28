
# EOS Elliptic-curve cryptography PHP library

## Introduction

Elliptic-curve cryptography (ECC) is used by the EOS Blockchain to implement
Public/Private key encryption. However EOS does abit more than just standard ECC.

This library was written to address this. it's basicly a wrapper around a generic ECC implemention.
[mdanter/ecc](https://packagist.org/packages/mdanter/ecc) to be more exact, however the API never
exposes this so it could change at any time without the code using this library will have to change.

This library exposes mainly 3 classes that you will deal with.

* PublicKey
* PrivateKey
* Signature

Here is a quick list of what EOS/Blockchain specific functionality is included in this library:

* Encode/Decode WIF (Wallet import format, [Base58](https://en.wikipedia.org/wiki/Base58)) Signatures,Private keys and Public keys.
* Ripe160md/Double Sha256 checksum used in WIF.
* Public Key recovery from Signatures.
* Canonical Signatures.

And of course on top of this standard functionality for a ECC library like 
signing messages, verifying signatures and so on.


## Install

You can install this using composer:

`composer require eosswedenorg/eos-ecc`

## Contribution

If you find a bug, have an idea for a new feature or something else that should be changed.
Please open an `issue` (or create a `pull request` if you have some code you want integrated)
on [Github](https://github.com/eosswedenorg/ecc-eos)

## Author

Henrik Hautakoski - [henrik@eossweden.org](mailto:henrik@eossweden.org)
