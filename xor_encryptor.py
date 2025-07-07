# xor_encryptor.py

import argparse
import os

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def process_file(file_path: str, key: str, encrypt: bool) -> str:
    with open(file_path, 'rb') as f:
        data = f.read()

    key_bytes = key.encode()
    processed_data = xor_encrypt_decrypt(data, key_bytes)

    suffix = '.enc' if encrypt else '.dec'
    out_file = file_path + suffix
    with open(out_file, 'wb') as f:
        f.write(processed_data)

    return out_file

def main():
    parser = argparse.ArgumentParser(description="Simple XOR file encryptor/decryptor.")
    parser.add_argument('-f', '--file', required=True, help='Path to input file')
    parser.add_argument('-k', '--key', required=True, help='Encryption key')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the file')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the file')

    args = parser.parse_args()

    if args.encrypt == args.decrypt:
        print("[!] Please choose either encryption (-e) or decryption (-d), but not both.")
        return

    operation = 'encryption' if args.encrypt else 'decryption'
    print(f"[*] Starting {operation}...")

    try:
        output = process_file(args.file, args.key, encrypt=args.encrypt)
        print(f"[+] {operation.capitalize()} complete. Output file: {output}")
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == '__main__':
    main()
