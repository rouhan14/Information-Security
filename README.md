# Enhanced HMAC Implementation in Python

This Python script implements an enhanced version of the Hash-based Message Authentication Code (HMAC) algorithm using the SHA1 hash function.

## Key Features

- **Modified Padding Scheme**: The padding scheme has been adjusted to append a different pattern or adjust the length representation, enhancing security and uniqueness of the HMAC algorithm.

- **DJB2-inspired Hashing Algorithm**: A small modification inspired by the DJB2 hashing algorithm has been incorporated to tailor the pads to the specific key provided, potentially enhancing the security of the HMAC algorithm.

- **Separation of Message Update and Finalization**: The script now separates the message update functionality into the `update` method, allowing incremental updates to the HMAC instance for improved flexibility.

- **Finalization Method**: A `finalize` method has been introduced to compute the final HMAC digest. This method ensures that the outer hash is updated with the outer pad and the inner hash before returning the resulting digest.

- **Hexadecimal Digest Representation**: The `hexdigest` method now returns a string of hexadecimal characters, making it consistent with the standard behavior of hash digest representations.

## How to Use

python hmac.py plaintext.txt
