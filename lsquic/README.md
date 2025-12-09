# LSQUIC Differential Cryptanalysis Attack

This directory contains a proof-of-concept differential cryptanalysis attack against the XXHash32 hash function used in LiteSpeed's LSQUIC implementation.

## Vulnerability Status

**Note**: This vulnerability has been responsibly disclosed to the LSQUIC maintainers and has been fixed in recent versions of LSQUIC. This proof-of-concept is provided for educational purposes to help security researchers understand differential cryptanalysis techniques against non-cryptographic hash functions.

## Overview

The attack applies differential cryptanalysis techniques to find input differences that produce hash collisions. By systematically searching through differential characteristics and reversing hash operations, the attack can generate numerous colliding inputs that degrade hash table performance.

## Requirements

- C++ compiler with C++11 support (g++, clang++)
- Standard C++ library

## Usage

### Building

Compile the attack code:

```bash
g++ -o diff_crypt diff_crypt.cpp -std=c++11 -O2
```

### Running the Attack

Generate differential pairs that produce collisions:

```bash
# Generate 100 differential pairs (default)
./diff_crypt

# Generate 50 differential pairs
./diff_crypt 50

# Generate and verify 100 differential pairs
./diff_crypt --test

# Generate and verify 200 differential pairs
./diff_crypt 200 --test
```

#### Command Line Options

- `[max_pairs]`: Maximum number of differential pairs to find (default: 100, upper bound: 2^32)
- `--test`: Run verification tests on found differentials and report pass/fail status

### Test Mode

When using `--test`, the program verifies that all found differentials produce actual collisions:
- Exit code 0: All tests passed
- Exit code 1: Some tests failed

This is useful for CI/CD pipelines and validating that the attack works correctly.

## Implementation Details

The attack works by:

1. **Reversing hash operations**: Computing what input chunk is needed to reach a target hash value from an intermediate state
2. **Testing differentials**: Verifying that input differences produce consistent hash collisions across random inputs and seeds
3. **Systematic search**: Iterating through the 32-bit difference space to find all valid differentials

The implementation uses modular inverses of XXHash32 constants to reverse hash rounds, enabling precise control over intermediate states.

## Files

- `diff_crypt.cpp` - Main attack implementation that finds and verifies differential characteristics
- `xxhash32.h` - Reference implementation of XXHash32 by Stephan Brumme (MIT License), with two functions added:
  - `hash_single_round()` - Instance method that computes hash with only a single round
  - `hash_single_round(input, length, seed)` - Static wrapper for single round computation
  - Modifications are clearly marked between `// NEW CODE` and `// END NEW CODE` comments

## Target

- **Implementation**: LiteSpeed LSQUIC (XXHash32)
- **Attack Type**: Differential cryptanalysis
- **Impact**: Hash table performance degradation leading to denial of service

## Licensing

The `xxhash32.h` file is based on Stephan Brumme's implementation, licensed under the MIT License. Modifications are clearly documented in the source code.
