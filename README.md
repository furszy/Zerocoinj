# Zerocoinj

## Introduction

Zerocoinj is a java full port from scratch from the well known libzerocoin library.
The libzerocoin library is a C++ library that implemented the core cryptographic routines of the Zerocoin protocol. Zerocoin is a distributed anonymous cash extension for Bitcoin-type (hash chain based) protocols. The protocol uses zero knowledge proofs to implement a fully decentralized coin laundry`.

The Zerocoin protocol is secure and uses well-studied cryptographic primitives. For a complete description of the protocol, see the Zerocoin white paper published in the IEEE Security & Privacy Symposium (2013) below.

* [Zerocoin Paper](http://zerocoin.org/media/pdf/ZerocoinOakland.pdf)

## Usage

The library was designed and coded for the PIVX blockchain as part of the Zerocoin Light Node Protocol.

- PIVX website (http://www.pivx.org)
- light/mobile wallet privacy using the [Zerocoin Light Node Protocol](https://pivx.org/wp-content/uploads/2018/11/Zerocoin_Light_Node_Protocol.pdf)


## WARNING

This library should not be used without have deep knowledge on the cryptographic primitives.


// If you get an error running the tests, then the native library is missing
-Djava.library.path="build/libs/bridge/shared/debug/"
