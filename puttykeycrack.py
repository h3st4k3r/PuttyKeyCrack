import base64
from itertools import product
from string import ascii_letters, digits, punctuation
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2
import threading
import time
from queue import Queue
import argparse
import sys

# Function to decrypt the file
def decrypt(passphrase, ciphertext):
    try:
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[48:]
        key = PBKDF2(passphrase, salt, dkLen=24, count=1000)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        padding_len = decrypted_data[-1]
        return decrypted_data[:-padding_len].decode('utf-8', errors='ignore')
    except Exception:
        return None

# Function to manage the queue of passwords and multithreading
def brute_force(cipher, base_pattern, dynamic_length, threads_count):
    # Global configuration
    characters = ascii_letters + digits + punctuation  # All possible characters
    queue = Queue()
    found = threading.Event()

    # Generate dynamic combinations
    print(f"Generating dynamic combinations of length {dynamic_length}...")
    dynamic_combinations = product(characters, repeat=dynamic_length)
    total_combinations = len(characters) ** dynamic_length

    for combo in dynamic_combinations:
        dynamic_part = ''.join(combo)
        queue.put(base_pattern.replace("**", dynamic_part))

    # Function executed by each thread
    def worker():
        while not queue.empty() and not found.is_set():
            password = queue.get()
            result = decrypt(password, cipher)
            if result and "Username" in result:
                print(f"\nPassword found!: {password}")
                print(result)
                found.set()
            queue.task_done()

    # Start multiple threads
    print(f"Starting {threads_count} threads...")
    threads = []
    for _ in range(threads_count):
        thread = threading.Thread(target=worker)
        thread.start()
        threads.append(thread)

    # Dynamic progress tracking
    start_time = time.time()
    while not found.is_set() and not queue.empty():
        completed = total_combinations - queue.qsize()
        elapsed = time.time() - start_time
        speed = completed / elapsed if elapsed > 0 else 0
        remaining = queue.qsize() / speed if speed > 0 else 0
        print(
            f"\rProgress: {completed}/{total_combinations} ({(completed/total_combinations)*100:.2f}%) | "
            f"Speed: {speed:.2f} attempts/sec | Remaining time: {remaining:.2f}s", end="", flush=True
        )
        time.sleep(1)

    # Wait for threads to finish
    for thread in threads:
        thread.join()

    # Final summary
    if not found.is_set():
        print("\nPassword not found. Try different parameters.")
    else:
        print("\nProcess completed successfully.")

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(
        description="Brute-force tool for decrypting Solar-PuTTY .dat files."
    )
    parser.add_argument(
        "--file", required=True, help="Path to the .dat file you want to decrypt."
    )
    parser.add_argument(
        "--pattern", required=True, help="Base pattern of the password with '**' as the dynamic part."
    )
    parser.add_argument(
        "--dynamic-length", type=int, default=4, help="Length of the dynamic part of the pattern (default is 4)."
    )
    parser.add_argument(
        "--threads", type=int, default=4, help="Number of threads to use (default is 4)."
    )
    parser.add_argument(
        "--help", action="help", help="Show this help message and exit."
    )

    args = parser.parse_args()

    # Load the file
    try:
        with open(args.file, "rb") as f:
            cipher = f.read()
    except FileNotFoundError:
        print(f"Error: File {args.file} not found.")
        sys.exit(1)

    # Start the brute-force process
    brute_force(cipher, args.pattern, args.dynamic_length, args.threads)

if __name__ == "__main__":
    main()
