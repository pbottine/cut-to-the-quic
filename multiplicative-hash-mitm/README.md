# Multiplicative Hash Meet-in-the-Middle

This repository implements a meet-in-the-middle approach to generate collisions on multiplicative hash functions producing a 32-bit digest.

## Requirements

Python 3.6+ (uses only standard library, no external dependencies)

## Usage

### Command Line

Generate collisions from the command line:

```bash
# Generate 10 collisions with default parameters (DJB hash-like)
python3 generic_mitm.py

# Generate 100 collisions with custom parameters
python3 generic_mitm.py -n 100 -p 7 -s 3 -i 5381 -m 33

# Output in hexadecimal format
python3 generic_mitm.py -f hex -n 50

# Output to file
python3 generic_mitm.py -o collisions.txt -n 1000

# Interactive mode with progress bar
python3 generic_mitm.py --interactive -n 500
```

#### Command Line Options

- `-f, --format`: Output format (`bytes`, `hex`, or `c`) - default: `bytes`
- `-o, --output`: Output file path (prints to console if not specified)
- `-p, --prefix`: Prefix size - default: `7`
- `-s, --suffix`: Suffix size (affects memory usage) - default: `3`
- `-i, --initial`: Initial hash value - default: `5387`
- `-m, --multiplier`: Hash multiplier - default: `31`
- `-n, --n-collisions`: Number of collisions to generate - default: `10`
- `--interactive`: Enable progress bar

### As a Python Module

You can also import and use the class programmatically:

```python
from generic_mitm import MultiplicativeHash

# Define an instance of a MultiplicativeHash with initial value 5381 and multiplier 33
# (Daniel J. Bernstein's djb2 algorithm)
mHash = MultiplicativeHash(5381, 33)

# The size of the colliding inputs corresponds to prefix_size + suffix_size
prefix_size = 8

# The suffix size dictates the time-memory tradeoff. A table of size 2^(suffix_size*8) will
# be created. The larger this value, the more time precomputations will take, but the quicker
# collisions will be generated after that. Currently, we upper bound this value to 3, which
# would result in a table of size 2^24, corresponding to over 200 MB for inputs of size 10.
suffix_size = 2

# The number of collisions to generate
n_collisions = 1000

collisions = mHash.meet_in_middle(prefix_size, suffix_size, n_collisions)
```

## How It Works

The meet-in-the-middle attack exploits the structure of multiplicative hash functions:

1. **Precomputation phase**: Generate a table of `2^(suffix_size*8)` hash values by computing the hash backwards from a target value
2. **Search phase**: Generate random prefixes and compute their forward hash values until one matches an entry in the precomputed table
3. **Collision found**: Concatenate the matching prefix and suffix to create a collision

This approach trades memory for time, making collision generation practical even for 32-bit hash functions.
