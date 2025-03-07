```markdown
# Introduction to Cryptography

## Use Basic Transcription and Substitution Ciphers and Keys to Encrypt Simple Messages

### Transcription Cipher

A transcription cipher rearranges the characters in the plaintext to create the ciphertext.

- **Example**: Columnar Transposition Cipher
  - Plaintext: `HELLO WORLD`
  - Key: `3 1 4 2`
  - Ciphertext: `LHOE LWRDO`

### Substitution Cipher

A substitution cipher replaces each character in the plaintext with another character.

- **Example**: Caesar Cipher
  - Plaintext: `HELLO`
  - Key: `3`
  - Ciphertext: `KHOOR`

## Understand How Encryption Supports Secure Communication Through the PAIN Framework

The PAIN framework stands for Privacy, Authentication, Integrity, and Non-repudiation.

- **Privacy**: Ensures that the message is only readable by the intended recipient.
- **Authentication**: Verifies the identity of the sender.
- **Integrity**: Ensures that the message has not been altered during transmission.
- **Non-repudiation**: Prevents the sender from denying that they sent the message.

### Example

- **Privacy**: Using AES encryption to encrypt the message.
- **Authentication**: Using digital signatures to verify the sender's identity.
- **Integrity**: Using hash functions to ensure the message has not been altered.
- **Non-repudiation**: Using public key infrastructure (PKI) to prevent denial of sending the message.

## Differentiate Between Encoding and Encrypting

- **Encoding**: Converts data into a different format using a scheme that is publicly available. It is used for data representation and transmission.
  - **Example**: Base64 encoding
    - Plaintext: `HELLO`
    - Encoded: `SEVMTE8=`
- **Encrypting**: Converts data into a different format using a secret key. It is used for data protection and confidentiality.
  - **Example**: AES encryption
    - Plaintext: `HELLO`
    - Key: `mysecretkey`
    - Ciphertext: `3ad77bb40d7a3660a89ecaf32466ef97`

## Calculate the Strength and Efficiency of Various Encryption Levels

### Key Length and Security

- **Symmetric Encryption**: The security of symmetric encryption algorithms depends on the key length.
  - **Example**: AES-128, AES-192, AES-256
    - AES-128: 128-bit key, considered secure
    - AES-192: 192-bit key, more secure
    - AES-256: 256-bit key, most secure

### Efficiency

- **Symmetric Encryption**: Generally faster and more efficient for large amounts of data.
  - **Example**: AES is faster than RSA for encrypting large files.
- **Asymmetric Encryption**: Slower and less efficient but provides better security for key exchange.
  - **Example**: RSA is used for secure key exchange, while AES is used for encrypting the actual data.

## Use the Symmetric Encryption Tool OpenSSL to Confidentially Transmit Secure Messages

OpenSSL is a powerful tool for implementing encryption and secure communication.

### Encrypt a Message

- **create key and IV
`openssl enc -pbkdf2 -nosalt -aes-256-cbc -k secretpass -P > key_and_iv`

```
root@ip-10-0-1-231:/home/sysadmin/cryptography/activity# cat key_and_iv 
key=6B6053A7D8C7499B4825CC60209177489A82473B636AE0804D9263038563D778
iv =B785E5C6BE76EA3C590D02A6C8254D21
root@ip-10-0-1-231:/home/sysadmin/cryptography/activity# openssl enc -pbkdf2 -nosalt -aes-256-cbc -in meeting.txt -out meeting.txt.enc -base64 -K 6B6053A7D8C7499B4825CC60209177489A82473B636AE0804D9263038563D778 -iv B785E5C6BE76EA3C590D02A6C8254D21


openssl enc -pbkdf2 -nosalt -aes-256-cbc -d -in meeting.txt.enc  -base64 -K 6B6053A7D8C7499B4825CC60209177489A82473B636AE0804D9263038563D778 -iv B785E5C6BE76EA3C590D02A6C8254D21
```


- **Command**:
  ```bash
  openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.txt -k mysecretkey
  ```
- **Explanation**: This command uses AES-256-CBC to encrypt the file `plaintext.txt` and outputs the encrypted file as `encrypted.txt` using the key `mysecretkey`.

### Decrypt a Message

- **Command**:
  ```bash
  openssl enc -aes-256-cbc -d -in encrypted.txt -out decrypted.txt -k mysecretkey
  ```
- **Explanation**: This command decrypts the file `encrypted.txt` and outputs the decrypted file as `decrypted.txt` using the key `mysecretkey`.

By understanding and applying these cryptographic techniques, you can enhance the security of your communications and protect sensitive information from unauthorized access.

```