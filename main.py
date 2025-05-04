import argparse
import logging
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
import os
import binascii

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes ciphertext to determine the likely block cipher mode.")
    parser.add_argument("ciphertext_file", help="Path to the file containing the ciphertext (in hex format).")
    parser.add_argument("--block_size", type=int, default=16, help="Block size in bytes (default: 16).  Common values: 8, 16")
    parser.add_argument("--threshold", type=float, default=0.9, help="Threshold for repetition detection (default: 0.9). Higher values are stricter.")
    parser.add_argument("--sample_size", type=int, default=1000, help="Sample size for frequency analysis (default: 1000). Higher values are more accurate but slower.")
    parser.add_argument("--enable_ctr_test", action="store_true", help="Enable statistical tests for CTR mode, which is time intensive.")

    return parser.parse_args()


def detect_ecb(ciphertext, block_size, threshold):
    """
    Detects ECB mode based on block repetition.
    """
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    block_counts = {}
    for block in blocks:
        block_counts[block] = block_counts.get(block, 0) + 1

    total_blocks = len(blocks)
    repeated_blocks = sum(count > 1 for count in block_counts.values())

    repetition_ratio = repeated_blocks / total_blocks if total_blocks > 0 else 0
    logging.debug(f"Repetition Ratio: {repetition_ratio}, Threshold: {threshold}")

    if repetition_ratio > threshold:
        return True
    return False


def detect_ctr_statistical_test(ciphertext, block_size, sample_size):
    """
    Performs statistical tests to detect CTR mode.  This is a simple check and
    may result in false positives.

    Note: this function is expensive.  It needs to be explicitly enabled in the
    command-line arguments.
    """

    if len(ciphertext) < block_size * sample_size:
      logging.warning("Ciphertext too small for reliable CTR analysis. Increase ciphertext size.")
      return False

    # Sample random blocks from the ciphertext
    import random
    samples = random.sample(range(0, len(ciphertext) - block_size, block_size), min(sample_size, len(ciphertext) // block_size))
    sample_blocks = [ciphertext[i:i + block_size] for i in samples]

    # Calculate byte frequencies for each position in the block
    byte_frequencies = [{} for _ in range(block_size)]
    for block in sample_blocks:
        for i in range(block_size):
            byte = block[i]
            byte_frequencies[i][byte] = byte_frequencies[i].get(byte, 0) + 1

    # Calculate the variance of byte frequencies for each position
    variances = []
    for i in range(block_size):
        frequencies = list(byte_frequencies[i].values())
        if not frequencies:
            variances.append(0)
            continue

        mean = sum(frequencies) / len(frequencies)
        variance = sum([(freq - mean) ** 2 for freq in frequencies]) / len(frequencies)
        variances.append(variance)

    # Check if the variances are uniformly low, indicating a keystream-like pattern
    # (this is a heuristic and can be adjusted)
    variance_threshold = 10  # Adjust as needed based on your data
    uniform = all(variance < variance_threshold for variance in variances)
    logging.debug(f"Variances: {variances}, Variance Threshold: {variance_threshold}, Uniform: {uniform}")

    return uniform

def main():
    """
    Main function to analyze the ciphertext and determine the block cipher mode.
    """
    args = setup_argparse()

    try:
        with open(args.ciphertext_file, 'r') as f:
            ciphertext_hex = f.read().strip()
        ciphertext = bytes.fromhex(ciphertext_hex)
    except FileNotFoundError:
        logging.error(f"Ciphertext file not found: {args.ciphertext_file}")
        sys.exit(1)
    except ValueError:
        logging.error("Invalid hex encoded ciphertext.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading ciphertext file: {e}")
        sys.exit(1)

    block_size = args.block_size
    threshold = args.threshold

    if len(ciphertext) % block_size != 0:
        logging.warning("Ciphertext length is not a multiple of the block size.  Padding may be used, or the file may be corrupted.")

    try:
        if detect_ecb(ciphertext, block_size, threshold):
            print("Likely mode: ECB (Electronic Codebook)")
        else:
            print("ECB not detected.")

        if args.enable_ctr_test:
            if detect_ctr_statistical_test(ciphertext, block_size, args.sample_size):
                print("Likely mode: CTR (Counter)")
            else:
                print("CTR not detected (statistical test).")
        else:
            print("CTR detection skipped. Use --enable_ctr_test to perform statistical CTR detection.")

        # Add other mode detection methods here (CBC, CFB, OFB, etc.)
        # These will require different analysis techniques.  For CBC, you'd look
        # for the absence of ECB-like patterns *and* the absence of CTR-like patterns.
        # CFB and OFB are harder to detect statistically without additional information.

    except Exception as e:
        logging.error(f"Error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()