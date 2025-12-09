# QUIC Hash DoS Attack Code

Proof-of-concept implementations demonstrating hash collision attacks against QUIC implementations, presented at Black Hat Europe 2025.

## Talk Information

**Cut to the QUIC: Slashing QUIC's Performance with a Hash DoS**
Black Hat Europe 2025
[Talk Details](https://www.blackhat.com/eu-25/briefings/schedule/index.html#cut-to-the-quic-slashing-quics-performance-with-a-hash-dos-48330)

## Overview

This repository contains proof-of-concept code demonstrating hash collision attacks against QUIC implementations:

### 1. xquic - Equivalent Substring Attack
A Python script that exploits the hash function used in Alibaba's XQUIC implementation through equivalent substring collision generation.

### 2. lsquic - Differential Cryptanalysis Attack
C++ code implementing a differential cryptanalysis attack against the XXHash32 hash function in LiteSpeed's LSQUIC implementation.

### 3. multiplicative-hash-mitm - Generic Meet-in-the-Middle Attack
A generic meet-in-the-middle attack implementation targeting 32-bit multiplicative hash functions.

## Vulnerability Status

**Note**: The vulnerabilities demonstrated in this repository have been responsibly disclosed and patched:
- **XQUIC**: Vulnerability fixed in recent versions
- **LSQUIC**: Vulnerability fixed in recent versions

This code is provided for educational purposes and to help security researchers understand these attack techniques.

## Disclaimer

This code is intended for educational and defensive security research purposes only. Do not use these techniques for malicious purposes or against systems you do not own or have explicit permission to test.

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
