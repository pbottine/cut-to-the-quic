# XQUIC Equivalent Substring Attack

This directory contains a proof-of-concept equivalent substring collision attack against the hash function used in Alibaba's XQUIC implementation.

## Vulnerability Status

**Note**: This vulnerability has been responsibly disclosed to the XQUIC maintainers and has been fixed in recent versions of XQUIC. This proof-of-concept is provided for educational purposes to help security researchers understand the attack technique.

## Overview

The attack exploits properties of the hash function to generate equivalent substrings that produce the same hash value, allowing for collision attacks that can degrade hash table performance.

## Requirements

Python 3.6+ (uses only standard library, no external dependencies)

## Usage

Generate colliding inputs using the provided Python script:

```bash
python3 gen_collisions.py
```

The script generates all 6-length permutations of carefully chosen 2-byte hex strings that produce hash collisions. These colliding inputs can be used to trigger worst-case performance in XQUIC's hash table implementation.

## Implementation Details

The attack uses a set of 2-byte hex values that have been identified to create equivalent substrings under XQUIC's hash function. By combining these values in different permutations, we can generate numerous inputs that all hash to the same value.

## Target

- **Implementation**: Alibaba XQUIC
- **Attack Type**: Equivalent substring collision
- **Impact**: Hash table performance degradation leading to denial of service
