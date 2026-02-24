package aescrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
)

var (
	ErrInvalidKeySize        = errors.New("invalid key size: must be 16, 24, or 32 bytes")
	ErrInvalidPadding        = errors.New("invalid padding")
	ErrInvalidPaddingSize    = errors.New("invalid padding size")
	ErrInvalidPaddingContent = errors.New("invalid padding content")
	ErrCiphertextTooShort    = errors.New("ciphertext too short")
	ErrCiphertextNotMultiple = errors.New("ciphertext is not a multiple of the block size")
	ErrInvalidIVSize         = errors.New("invalid IV size: must equal AES block size (16)")
	ErrInvalidHexLength      = errors.New("invalid hex length")
)

// CIPHER OBJECT (STATELESS)
type AESCipher struct {
	block cipher.Block
}

// New creates AES cipher (supports AES-128/192/256 automatically)
func New(key []byte) (*AESCipher, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AESCipher{block: block}, nil
}

// ENCRYPT
// Output format: IV || CIPHERTEXT
func (a *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := a.block.BlockSize()

	// Padding
	plaintext = pkcs7Padding(plaintext, blockSize)

	// Allocate result: IV + ciphertext
	result := make([]byte, blockSize+len(plaintext))

	iv := result[:blockSize]

	// Random IV per message
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(a.block, iv)
	mode.CryptBlocks(result[blockSize:], plaintext)

	return result, nil
}

// ENCRYPT WITH USER IV
// output: CIPHERTEXT
func (a *AESCipher) EncryptWithIV(iv, plaintext []byte) ([]byte, error) {
	blockSize := a.block.BlockSize()

	if err := validateIV(iv, blockSize); err != nil {
		return nil, err
	}

	plaintext = pkcs7Padding(plaintext, blockSize)
	result := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(a.block, iv)
	mode.CryptBlocks(result, plaintext)

	return result, nil
}

// DECRYPT
// Expect format: IV || CIPHERTEXT
func (a *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	blockSize := a.block.BlockSize()

	if len(ciphertext) < blockSize {
		return nil, ErrCiphertextTooShort
	}

	iv := ciphertext[:blockSize]
	data := ciphertext[blockSize:]

	if len(data)%blockSize != 0 {
		return nil, ErrCiphertextNotMultiple
	}

	mode := cipher.NewCBCDecrypter(a.block, iv)
	mode.CryptBlocks(data, data)

	return pkcs7Unpadding(data, blockSize)
}

// DECRYPT WITH SEPARATE IV
func (a *AESCipher) DecryptWithIV(iv, ciphertext []byte) ([]byte, error) {
	blockSize := a.block.BlockSize()

	if err := validateIV(iv, blockSize); err != nil {
		return nil, err
	}

	if len(ciphertext)%blockSize != 0 {
		return nil, ErrCiphertextNotMultiple
	}

	mode := cipher.NewCBCDecrypter(a.block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return pkcs7Unpadding(ciphertext, blockSize)
}

// PKCS7 PADDING (CRYPTO SAFE)
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

// PKCS7 UNPADDING
func pkcs7Unpadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, ErrInvalidPaddingSize
	}

	padding := int(data[length-1])

	if padding == 0 || padding > blockSize || padding > length {
		return nil, ErrInvalidPadding
	}

	// constant-time padding verification
	var invalid byte
	for i := 0; i < padding; i++ {
		invalid |= data[length-1-i] ^ byte(padding)
	}

	if subtle.ConstantTimeByteEq(invalid, 0) != 1 {
		return nil, ErrInvalidPaddingContent
	}

	return data[:length-padding], nil
}

// VALIDATION
func validateKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return ErrInvalidKeySize
	}
}

func validateIV(iv []byte, blockSize int) error {
	if len(iv) != blockSize {
		return ErrInvalidIVSize
	}
	return nil
}

// HELPER
func BytesToHex(src []byte) string {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return string(dst)
}

func HexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, ErrInvalidHexLength
	}
	return hex.DecodeString(s)
}
