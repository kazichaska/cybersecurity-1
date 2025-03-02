```markdown
# Different Types of Ciphers and Encryption

Cryptography involves various types of ciphers and encryption methods to secure data. This document outlines some of the most common types with examples.

## Substitution Ciphers

Substitution ciphers replace each character in the plaintext with another character.

### Caesar Cipher

A simple substitution cipher where each letter in the plaintext is shifted a certain number of places down the alphabet.

- **Example**:
  - Plaintext: `HELLO`
  - Key: `3`
  - Ciphertext: `KHOOR`

### Atbash Cipher

A substitution cipher where each letter in the plaintext is mapped to its reverse in the alphabet.

- **Example**:
  - Plaintext: `HELLO`
  - Ciphertext: `SVOOL`

## Transposition Ciphers

Transposition ciphers rearrange the characters in the plaintext to create the ciphertext.

### Columnar Transposition Cipher

The plaintext is written in rows and then read column by column according to a specified key.

- **Example**:
  - Plaintext: `HELLO WORLD`
  - Key: `3 1 4 2`
  - Ciphertext: `LHOE LWRDO`

## Symmetric Encryption

Symmetric encryption uses the same key for both encryption and decryption.

### Advanced Encryption Standard (AES)

AES is a widely used symmetric encryption algorithm that supports key sizes of 128, 192, and 256 bits.

- **Example**:
  - Plaintext: `HELLO`
  - Key: `mysecretkey`
  - Ciphertext: `3ad77bb40d7a3660a89ecaf32466ef97`

- **OpenSSL Example**:
  - Encrypt:
    ```bash
    openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.txt -k mysecretkey
    ```
  - Decrypt:
    ```bash
    openssl enc -aes-256-cbc -d -in encrypted.txt -out decrypted.txt -k mysecretkey
    ```

### Data Encryption Standard (DES)

DES is an older symmetric encryption algorithm that uses a 56-bit key.

- **Example**:
  - Plaintext: `HELLO`
  - Key: `mykey123`
  - Ciphertext: `85e813540f0ab405`

- **OpenSSL Example**:
  - Encrypt:
    ```bash
    openssl enc -des-cbc -salt -in plaintext.txt -out encrypted.txt -k mykey123
    ```
  - Decrypt:
    ```bash
    openssl enc -des-cbc -d -in encrypted.txt -out decrypted.txt -k mykey123
    ```

## Asymmetric Encryption

Asymmetric encryption uses a pair of keys: a public key for encryption and a private key for decryption.

### RSA (Rivest-Shamir-Adleman)

RSA is a widely used asymmetric encryption algorithm that relies on the mathematical properties of large prime numbers.

- **Example**:
  - Plaintext: `HELLO`
  - Public Key: `(e, n)`
  - Private Key: `(d, n)`
  - Ciphertext: `Encrypted with public key`

- **OpenSSL Example**:
  - Generate Keys:
    ```bash
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in private_key.pem -out public_key.pem
    ```
  - Encrypt:
    ```bash
    openssl rsautl -encrypt -inkey public_key.pem -pubin -in plaintext.txt -out encrypted.txt
    ```
  - Decrypt:
    ```bash
    openssl rsautl -decrypt -inkey private_key.pem -in encrypted.txt -out decrypted.txt
    ```

## Hash Functions

Hash functions generate a fixed-size hash value from input data, ensuring data integrity.

### SHA-256 (Secure Hash Algorithm 256-bit)

SHA-256 produces a 256-bit hash value from input data.

- **Example**:
  - Input: `HELLO`
  - Hash: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`

- **OpenSSL Example**:
  ```bash
  echo -n "HELLO" | openssl dgst -sha256
  ```

### MD5 (Message Digest Algorithm 5)

MD5 produces a 128-bit hash value from input data.

- **Example**:
  - Input: `HELLO`
  - Hash: `8b1a9953c4611296a827abf8c47804d7`

- **OpenSSL Example**:
  ```bash
  echo -n "HELLO" | openssl dgst -md5
  ```

## Stream Ciphers

Stream ciphers encrypt plaintext one byte at a time, producing a stream of ciphertext.

### RC4 (Rivest Cipher 4)

RC4 is a widely used stream cipher known for its simplicity and speed.

- **Example**:
  - Plaintext: `HELLO`
  - Key: `mysecretkey`
  - Ciphertext: `Encrypted stream`

## Block Ciphers

Block ciphers encrypt data in fixed-size blocks, typically 64 or 128 bits.

### Blowfish

Blowfish is a symmetric block cipher that uses a variable-length key from 32 to 448 bits.

- **Example**:
  - Plaintext: `HELLO`
  - Key: `mysecretkey`
  - Ciphertext: `Encrypted block`

- **OpenSSL Example**:
  - Encrypt:
    ```bash
    openssl enc -bf-cbc -salt -in plaintext.txt -out encrypted.txt -k mysecretkey
    ```
  - Decrypt:
    ```bash
    openssl enc -bf-cbc -d -in encrypted.txt -out decrypted.txt -k mysecretkey
    ```

### Twofish

Twofish is a symmetric block cipher that uses a 128-bit block size and key sizes up to 256 bits.

- **Example**:
  - Plaintext: `HELLO`
  - Key: `mysecretkey`
  - Ciphertext: `Encrypted block`

By understanding and applying these different types of ciphers and encryption methods, you can enhance the security of your data and protect it from unauthorized access.

```