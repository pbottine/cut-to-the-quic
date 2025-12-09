# `xquic` Equivalent Substring Attack

This directory contains a proof-of-concept equivalent substring collision attack against the hash function originally used in Alibaba's `xquic` implementation (prior to version 1.8.2).

## Overview

The attack exploits properties of the hash function to generate equivalent substrings that produce the same hash value, allowing for very efficient generation of a large number of collisions.

## Requirements

Python 3.6+ (uses only standard library, no external dependencies)

## Usage

Generate colliding inputs using the provided Python script:

```bash
python3 gen_collisions.py
```

