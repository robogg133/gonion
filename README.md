# Gonion
![Gonion](icon.png)

A pure Go implementation of the Tor client protocol.

> No CGO.  
> No bindings to the official Tor daemon.  
> No wrappers around `libtor`.  
> Gonion is a complete reimplementation of the Tor client stack written entirely in Go.

The goal of this project is to implement the Tor protocol from scratch while keeping the codebase understandable, auditable, hackable, lightweight, and fully portable.

---

# Design Philosophy

Gonion does not try to behave like a traditional Tor wrapper.

Most Tor integrations work by:

- spawning the Tor daemon,
- opening a local SOCKS5 proxy,
- and forwarding all traffic through it.

Gonion takes a completely different approach.

Instead of exposing a SOCKS5 proxy and routing traffic externally, the framework contains its own native Tor networking stack and its own dialer implementation.

Applications communicate directly with Gonion internally, without needing a local proxy server.

This changes several things:

- only the relay connections themselves are visible,
- applications do not need to expose a local SOCKS port,
- there is less local network surface,
- there are fewer detectable Tor-related artifacts,
- and the system uses fewer external resources.

The objective is to make the Tor client integration feel more embedded, self-contained, lightweight, and harder to fingerprint compared to the traditional “spawn tor + connect to SOCKS5” model.

The framework aims to operate as if the Tor logic were part of the application itself instead of an external daemon.

---

# Project Goals

Gonion is not just a SOCKS proxy or a minimal Tor connector.

The objective is to build a **fully functional Tor client implementation** capable of handling the complete Tor networking stack directly in Go.

The long-term goals include:

- Full Tor link protocol implementation
- Circuit creation and management
- 3-hop anonymous circuits
- Consensus fetching and parsing
- Stream multiplexing
- Hidden services (`.onion`)
- Introduction points
- DNS resolution through Tor
- Circuit rotation
- Relay family awareness
- IPv4 and IPv6 support
- Spec-compatible behavior
- Native dialer support
- Tor traffic obfuscation

The final objective is to have a standalone Tor client implementation that can operate independently without requiring the official Tor daemon.

---

# Why Pure Go?

Most Tor-related Go projects either:

- wrap the Tor daemon,
- depend on external binaries,
- use CGO bindings,
- or only implement partial functionality.

Gonion avoids all of that.

Everything is implemented directly in Go:

- TLS handling
- Cell serialization
- Circuit cryptography
- Relay protocol
- Stream management
- Hidden service protocols
- Directory communication
- Transport obfuscation
- Native Tor dialing

This brings several advantages:

- Easier cross compilation
- Better portability
- Simpler deployment
- Easier static linking
- Better understanding of the protocol internals
- Full control over the networking stack
- No external runtime dependencies

---

# Native Dialer

Instead of exposing a SOCKS5 proxy and forcing applications to connect through localhost, Gonion provides its own native Tor dialer implementation.

This means applications can establish Tor connections directly through the framework itself.

The advantages include:

- no local SOCKS5 server,
- no localhost proxy artifacts,
- fewer open ports,
- lower overhead,
- reduced external visibility,
- simpler embedding into applications,
- and tighter control over connection handling.

The framework aims to minimize unnecessary exposure and operate using as little externally visible infrastructure as possible.

---

# Pluggable Transports & Obfuscation

Another major objective of Gonion is native support for Tor obfuscation transports.

The framework already includes support for:

- obfs4

The long-term goal is supporting multiple pluggable transports and censorship circumvention systems, including:

- snowflake
- webtunnel
- custom transports

The architecture is designed so transports can be integrated directly into the networking layer instead of relying on external wrappers whenever possible.

This allows:

- censorship bypassing,
- traffic obfuscation,
- DPI resistance,
- bridge support,
- and more stealthy relay communication.

---

# Current State

Gonion is still under active development and is not considered production ready yet.

At the moment, the framework already implements large parts of the Tor low-level protocol stack, including:

- Tor link protocol negotiation
- TLS relay connections
- CERTS validation
- NETINFO handling
- CREATE_FAST circuits
- Relay cell encoding/decoding
- SENDME flow control
- Consensus fetching
- Consensus parsing
- Microdescriptor fetching
- Microdescriptor parsing
- Relay selection algorithms
- Stream infrastructure
- Circuit infrastructure
- Directory requests through Tor circuits
- obfs4 support
- Native Tor dialing

The architecture is designed to eventually support the entire Tor client protocol stack.

---

# Architecture

The project is structured around the actual Tor protocol layers.

## Connection Layer

Responsible for:

- TLS connections to relays
- Version negotiation
- CERTS handling
- AUTH_CHALLENGE handling
- NETINFO exchange
- Raw Tor cell transport
- Pluggable transports
- Obfuscation layers

## Circuit Layer

Responsible for:

- Circuit lifecycle
- Cryptographic state
- Relay encryption/decryption
- Flow control
- Relay forwarding
- SENDME handling
- Circuit teardown

## Stream Layer

Responsible for:

- Multiplexed streams over circuits
- Data transfer
- Directory streams
- Future SOCKS and DNS support

# Hidden Services

A major goal of Gonion is implementing native hidden service support.
The implementation aims to follow the Tor specifications as closely as possible.

---

# Performance Philosophy

The project aims to balance:

- correctness,
- protocol compatibility,
- low allocations,
- low overhead,
- low visibility,
- minimal external exposure,
- and maintainable code.

Some parser sections are intentionally simple for now and may be optimized later once the protocol implementation stabilizes.

---

# Security

This project deals with anonymous networking and cryptographic protocols.

Even though many protocol parts are already implemented, the framework should currently be considered experimental.

Security auditing, edge-case handling, hardening, and spec verification are still ongoing.

---

# Status

This project is a work in progress.

The API is unstable and may change frequently while the protocol implementation evolves.