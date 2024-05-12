import sys
from hmac import HMAC
from dotenv import load_dotenv
load_dotenv()
import os

key = os.getenv("KEY")
with open("plaintext.txt", 'r') as ofile:
    text = ofile.readlines()
    text = text[0]

h = HMAC(key.encode("utf-8"))  # Encode the Unicode key back to bytes
h.update(text.encode("utf-8"))
hmac_hash = h.hexdigest()

def brute_force_hmac(keys, target_hash, content):
    for key in keys:
        h = HMAC(key.encode())
        h.update(content)
        hmac_hash = h.hexdigest()
        if hmac_hash == target_hash:
            return key
    return None

def main():
    potential_keys = ["password123", "secret", "key123", "MySecretKey123"]

    content = b"Hello, world!"
    target_hash = hmac_hash
    key_found = brute_force_hmac(potential_keys, target_hash, content)
    if key_found:
        print("Brute force successful! Key found:", key_found)
    else:
        print("Brute force unsuccessful. Key not found.")

if __name__ == "__main__":
    main()
