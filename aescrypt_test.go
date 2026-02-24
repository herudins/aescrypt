package aescrypt

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	key128 = []byte("1234567890123456")
	key192 = []byte("123456789012345678901234")
	key256 = []byte("12345678901234567890123456789012")
	iv     = []byte("INITVECTOR123456")
)

// HELPERS
func mustNewCipher(t *testing.T, key []byte) *AESCipher {
	c, err := New(key)
	require.NoError(t, err)
	require.NotNil(t, c)
	return c
}

// KEY VALIDATION
func TestKeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{"AES-128", key128, false},
		{"AES-192", key192, false},
		{"AES-256", key256, false},
		{"Invalid", []byte("short"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	c := mustNewCipher(t, key256)

	testCases := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("short text"),
		bytes.Repeat([]byte("A"), 15),
		bytes.Repeat([]byte("B"), 16),
		bytes.Repeat([]byte("C"), 31),
		bytes.Repeat([]byte("D"), 32),
		bytes.Repeat([]byte("E"), 1000),
	}

	for _, plain := range testCases {
		t.Run(strconv.Itoa(len(plain)), func(t *testing.T) {
			//Without custom IV
			enc, err := c.Encrypt(plain)
			require.NoError(t, err)

			dec, err := c.Decrypt(enc)
			require.NoError(t, err)

			assert.Equal(t, plain, dec)

			//With custom IV
			enc, err = c.EncryptWithIV(iv, plain)
			require.NoError(t, err)

			dec, err = c.DecryptWithIV(iv, enc)
			require.NoError(t, err)

			assert.Equal(t, plain, dec)
		})
	}
}

// WRONG KEY
func TestWrongKey(t *testing.T) {
	c1 := mustNewCipher(t, key128)
	c2 := mustNewCipher(t, key256)

	//Without custom IV
	enc, err := c1.Encrypt([]byte("secret message"))
	require.NoError(t, err)

	_, err = c2.Decrypt(enc)
	assert.Error(t, err)

	//With custom IV
	enc, err = c1.EncryptWithIV(iv, []byte("secret message"))
	require.NoError(t, err)

	_, err = c2.DecryptWithIV(iv, enc)
	assert.Error(t, err)
}

// WRONG IV
func TestWrongIV(t *testing.T) {
	c := mustNewCipher(t, key128)

	wrongIV := []byte("DIFFERENTVECTOR!!")

	//Without custom IV
	enc, err := c.Encrypt([]byte("hello"))
	require.NoError(t, err)

	fullEnc := append(wrongIV, enc...)
	_, err = c.Decrypt(fullEnc)
	assert.Error(t, err)

	//With custom IV
	enc, err = c.EncryptWithIV(iv, []byte("hello"))
	require.NoError(t, err)

	_, err = c.DecryptWithIV(wrongIV, enc)
	assert.Error(t, err)
}

// IV VALIDATION
func TestInvalidIV(t *testing.T) {
	c := mustNewCipher(t, key128)

	_, err := c.EncryptWithIV([]byte("short"), []byte("hello"))
	assert.Error(t, err)
}

// EMPTY PLAINTEXT
func TestEmptyPlaintext(t *testing.T) {
	c := mustNewCipher(t, key128)

	//Without custom IV
	enc, err := c.Encrypt([]byte{})
	require.NoError(t, err)

	dec, err := c.Decrypt(enc)
	require.NoError(t, err)

	assert.Empty(t, dec)

	//With custom IV
	enc, err = c.EncryptWithIV(iv, []byte{})
	require.NoError(t, err)

	dec, err = c.DecryptWithIV(iv, enc)
	require.NoError(t, err)

	assert.Empty(t, dec)
}

// ALL PADDING LENGTHS
func TestAllPaddingSizes(t *testing.T) {
	c := mustNewCipher(t, key128)

	for i := 1; i <= 32; i++ {
		data := bytes.Repeat([]byte("A"), i)

		//Without custom IV
		enc, err := c.Encrypt(data)
		require.NoError(t, err)

		dec, err := c.Decrypt(enc)
		require.NoError(t, err)

		assert.Equal(t, data, dec, "padding failed at len=%d", i)

		//With custom IV
		enc, err = c.EncryptWithIV(iv, data)
		require.NoError(t, err)

		dec, err = c.DecryptWithIV(iv, enc)
		require.NoError(t, err)

		assert.Equal(t, data, dec, "padding failed at len=%d with custom IV", i)
	}
}

// CORRUPTED CIPHERTEXT
func TestCorruptedCiphertext(t *testing.T) {
	c := mustNewCipher(t, key128)

	enc, err := c.EncryptWithIV(iv, []byte("important data"))
	require.NoError(t, err)

	enc[len(enc)-1] ^= 0xFF

	_, err = c.Decrypt(enc)
	assert.Error(t, err)
}

// TOO SHORT
func TestTooShortCiphertext(t *testing.T) {
	c := mustNewCipher(t, key128)

	_, err := c.Decrypt([]byte("short"))
	assert.Error(t, err)
}

// NOT BLOCK MULTIPLE
func TestNotBlockMultiple(t *testing.T) {
	c := mustNewCipher(t, key128)

	data := append(iv, []byte("123")...)

	_, err := c.Decrypt(data)
	assert.Error(t, err)
}

// RANDOM STRESS TEST
func TestRandomStress(t *testing.T) {
	c := mustNewCipher(t, key256)

	for i := 0; i < 100; i++ {
		size := 1 + i*7
		buf := make([]byte, size)
		_, _ = rand.Read(buf)

		//Without custom IV
		enc, err := c.Encrypt(buf)
		require.NoError(t, err)

		dec, err := c.Decrypt(enc)
		require.NoError(t, err)

		assert.Equal(t, buf, dec)

		//With custom IV
		enc, err = c.EncryptWithIV(iv, buf)
		require.NoError(t, err)

		dec, err = c.DecryptWithIV(iv, enc)
		require.NoError(t, err)

		assert.Equal(t, buf, dec)
	}
}

// BENCHMARKS
func BenchmarkEncrypt(b *testing.B) {
	c, _ := New(key256)
	data := bytes.Repeat([]byte("A"), 1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = c.Encrypt(data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	c, _ := New(key256)
	data := bytes.Repeat([]byte("A"), 1024)
	enc, _ := c.Encrypt(data)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = c.Decrypt(enc)
	}
}

func BenchmarkEncryptWithIv(b *testing.B) {
	c, _ := New(key256)
	data := bytes.Repeat([]byte("A"), 1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = c.EncryptWithIV(iv, data)
	}
}

func BenchmarkDecryptWithIv(b *testing.B) {
	c, _ := New(key256)
	data := bytes.Repeat([]byte("A"), 1024)
	enc, _ := c.EncryptWithIV(iv, data)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = c.DecryptWithIV(iv, enc)
	}
}
