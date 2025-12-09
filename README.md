# QUIC Hash DoS Attack Code

Proof-of-concept implementations of three attacks to generate collisions on non-cryptographic hash functions used in several QUIC implementations, presented at Black Hat Europe 2025 as part of the talk
[**Cut to the QUIC: Slashing QUIC's Performance with a Hash DoS**](https://www.blackhat.com/eu-25/briefings/schedule/index.html#cut-to-the-quic-slashing-quics-performance-with-a-hash-dos-48330) and following a [coordinated disclosure effort in February 2025](https://github.com/ncc-pbottine/QUIC-Hash-Dos-Advisory).

## Overview

This repository contains proof-of-concept implementations of different methods to generate collisions on non-cryptographic hash functions used in several QUIC implementations:

### 1. `xquic` - Equivalent Substring Attack
A Python script that generates collisions for the hash function used in Alibaba's `xquic` implementation (used in version 1.8.1 and all earlier versions) through an equivalent substring attack.

### 2. `lsquic` - Differential Cryptanalysis Attack
C++ code implementing a differential cryptanalysis attack against the XXHash32 hash function in LiteSpeed's `lsquic` implementation (used in version 4.0.12 and all earlier versions).

### 3. multiplicative-hash-mitm - Generic Meet-in-the-Middle Attack
A generic meet-in-the-middle attack implementation targeting 32-bit multiplicative hash functions.

## Vulnerability Status

**Note**: The vulnerabilities demonstrated in this repository have been responsibly disclosed and patched:
- **`xquic`**: Vulnerability fixed in version 1.8.2.
- **`lsquic`**: Vulnerability fixed in version 4.2.0.

This code is provided for educational purposes and to help security researchers understand these attack techniques.

## Repository Structure

```
├── xquic/                      # Equivalent substring attack (Python)
├── lsquic/                     # Differential cryptanalysis attack (C++)
└── multiplicative-hash-mitm/   # Generic meet-in-the-middle attack (Python)
```

## Getting Started

Detailed instructions for each attack implementation can be found in their respective directories.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

This repository includes third-party code (lsquic/xxhash32.h) by Stephan Brumme, also licensed under the MIT License.
