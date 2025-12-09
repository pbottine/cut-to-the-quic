# `lsquic` Differential Cryptanalysis Attack

This directory contains a proof-of-concept differential cryptanalysis attack against the XXHash32 hash function originally used in LiteSpeed's [`lsquic`](https://github.com/litespeedtech/lsquic) implementation (prior to version 1.8.2).

## Overview

The attack applies differential cryptanalysis techniques to find input differences that produce hash collisions. Given a starting 8-byte array `A || B` and its corresponding hash, the attack finds pairs of differentials `(D1, D2)` such that `XXHash32(A||B) = XXHash32(A+D1||B+D2)` by

1. Iterating through the 32-bit search space to generate a first differential `D1`
2. Compute `D2` by reversing the hash operation from the target hash
3. Testing whether the `(D1, D2)` pair produces a hash collisions across random seeds

## Requirements

- C++ compiler with C++11 support (g++, clang++)
- Standard C++ library

### Building

Compile the attack code:

```bash
g++ -o diff_crypt diff_crypt.cpp -std=c++11 -O2
```

## Usage

Generate differential pairs that produce collisions:

```bash
# Generate 100 differential pairs (default)
./diff_crypt

# Generate 50 differential pairs
./diff_crypt 50

# Generate 100 pairs, print only the total count
./diff_crypt --quiet

# Generate 50 pairs in quiet mode
./diff_crypt 50 --quiet

# Generate and verify 100 differential pairs
./diff_crypt --test

# Generate and verify 200 differential pairs
./diff_crypt 200 --test

# Combine quiet mode with test mode
./diff_crypt 50 --quiet --test
```

#### Command Line Options

- `[max_pairs]`: Maximum number of differential pairs to find (default: 100, upper bound: 2^32)
- `--test`: Run verification tests on found differentials and report pass/fail status
- `--quiet` or `-q`: Print only the total count of pairs found, not individual pairs (useful for large collision sets)

### Test Mode

When using `--test`, the program verifies that all found differentials produce actual collisions:
- Exit code 0: All tests passed
- Exit code 1: Some tests failed

## Licensing

The `xxhash32.h` file is based on Stephan Brumme's implementation, licensed under the MIT License. Modifications are clearly documented in the source code.
