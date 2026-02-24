# Go AES-CBC Secure Encryption

This package provides a secure AES-CBC encryption and decryption implementation in Go with:

* User supplied IV (Initialization Vector)
* Strict IV validation
* Constant-time PKCS#7 padding verification (timing attack resistant)
* Safe error handling (no oracle leakage)

The goal of this project is educational + production-safe cryptographic usage for backend services that require deterministic IV input while still maintaining strong security guarantees.

---

## Why This Exists

Many encryption examples online are insecure because they:

* Accept arbitrary IV without validation
* Leak padding errors (padding oracle vulnerability)
* Use non-constant-time comparisons
* Panic on malformed ciphertext

This implementation fixes all of those.

---

## Security Properties

### 1. Constant-Time Padding Validation

Prevents padding oracle attacks by verifying PKCS#7 padding without early exit.

### 2. IV Validation

The IV must:

* Be exactly 16 bytes (AES block size)
* Not be all zeros
* Not repeat simple patterns (basic entropy check)

### 3. Error Hardening

Decryption never reveals whether failure was caused by:

* Wrong key
* Wrong IV
* Corrupted ciphertext
* Wrong padding

All failures return the same error.

---

## Installation

```bash
go get github.com/herudins/aescrypt
```

---

## Usage

### Import

```go
import "github.com/herudins/aescrypt"
```

---

### Encrypt & Decrypt With Random IV

```go
package main

import "github.com/herudins/aescrypt"

func main(){
    key := []byte("example key 1234example key 1234") // 32 bytes
	plain := []byte("hello world")

	aesC, err := aescrypt.New(key)
	if err != nil {
		panic(err)
	}

	ciphertext, err := aesC.Encrypt(plain)
	if err != nil {
		panic(err)
	}

	fmt.Println("Chippertext hex format:", aescrypt.BytesToHex(ciphertext))

	plainText, err := aesC.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("Plain Text:", string(plainText))
}
```

---

### Encrypt & Decrypt With Custom IV

```go
package main

import "github.com/herudins/aescrypt"

func main(){
    key := []byte("example key 1234example key 1234") // 32 bytes
	iv := []byte("INITVECTOR123456")
	plain := []byte("hello world")

	aesC, err := aescrypt.New(key)
	if err != nil {
		panic(err)
	}

	ciphertext, err := aesC.EncryptWithIV(iv, plain)
	if err != nil {
		panic(err)
	}

	fmt.Println("Chippertext hex format:", aescrypt.BytesToHex(ciphertext))

	plainText, err := aesC.DecryptWithIV(iv, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("Plain Text:", string(plainText))
}
```

---

## IV Rules

The IV must follow these constraints:

| Rule                 | Reason                         |
| -------------------- | ------------------------------ |
| 16 bytes             | AES block size                 |
| Not all zero         | Prevent predictable ciphertext |
| Not repeated pattern | Prevent low entropy attacks    |

---

## Running Tests

```bash
go test ./... -cover
```
---

## Test Cases Covered

* Valid encryption/decryption
* Wrong key
* Wrong IV
* Short IV
* Zero IV
* Pattern IV
* Corrupted ciphertext
* Corrupted padding
* Truncated ciphertext
* Empty plaintext
* Large plaintext

---

## Cryptography Notes

This uses:

* AES-256
* CBC mode
* PKCS#7 padding
* Constant-time padding verification

This package intentionally does NOT implement authentication (MAC / AEAD).

If you need authenticated encryption, use AES-GCM instead.

---

## Recommended Production Usage

For best security:

1. Use random IV per message
2. Include HMAC or use AEAD
3. Never reuse IV + key pair

This package exists for systems that must accept external IV (legacy protocol, banking ISO8583, hardware devices, etc.)

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
