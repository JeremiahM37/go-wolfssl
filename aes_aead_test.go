package wolfSSL

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

// Verify AesGcmAEAD satisfies cipher.AEAD at compile time.
var _ cipher.AEAD = (*AesGcmAEAD)(nil)

func TestAesGcmAEAD_NonceAndOverhead(t *testing.T) {
	var key [AES_256_KEY_SIZE]byte
	a := NewAesGcmAEAD(key)

	if a.NonceSize() != AES_IV_SIZE {
		t.Fatalf("NonceSize() = %d, want %d", a.NonceSize(), AES_IV_SIZE)
	}
	if a.Overhead() != AES_BLOCK_SIZE {
		t.Fatalf("Overhead() = %d, want %d", a.Overhead(), AES_BLOCK_SIZE)
	}
}

func TestAesGcmAEAD_SealOpen_RoundTrip(t *testing.T) {
	var key [AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(i)
	}
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}

	plaintext := []byte("Hello, wolfCrypt AES-GCM AEAD!")

	ciphertext := a.Seal(nil, nonce, plaintext, nil)

	// ciphertext should be len(plaintext) + Overhead
	expectedLen := len(plaintext) + a.Overhead()
	if len(ciphertext) != expectedLen {
		t.Fatalf("Seal: ciphertext len = %d, want %d", len(ciphertext), expectedLen)
	}

	// ciphertext should differ from plaintext
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Fatal("Seal: ciphertext matches plaintext (encryption did nothing)")
	}

	decrypted, err := a.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Open: got %q, want %q", decrypted, plaintext)
	}
}

func TestAesGcmAEAD_SealOpen_WithAAD(t *testing.T) {
	var key [AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	plaintext := []byte("authenticated additional data test")
	aad := []byte("this is additional data")

	ciphertext := a.Seal(nil, nonce, plaintext, aad)

	// Decrypt with correct AAD
	decrypted, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open with correct AAD: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Open: got %q, want %q", decrypted, plaintext)
	}

	// Decrypt with wrong AAD should fail
	_, err = a.Open(nil, nonce, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Fatal("Open with wrong AAD should have failed")
	}
}

func TestAesGcmAEAD_SealOpen_EmptyPlaintext(t *testing.T) {
	var key [AES_256_KEY_SIZE]byte
	key[0] = 0x42
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	plaintext := []byte{}

	ciphertext := a.Seal(nil, nonce, plaintext, nil)
	if len(ciphertext) != a.Overhead() {
		t.Fatalf("Seal empty: ciphertext len = %d, want %d (tag only)", len(ciphertext), a.Overhead())
	}

	decrypted, err := a.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("Open empty: got %d bytes, want 0", len(decrypted))
	}
}

func TestAesGcmAEAD_DstAppend(t *testing.T) {
	var key [AES_256_KEY_SIZE]byte
	key[1] = 0xFF
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	plaintext := []byte("dst append test")

	// Seal with non-nil dst prefix
	prefix := []byte("PREFIX:")
	ciphertext := a.Seal(prefix, nonce, plaintext, nil)
	if !bytes.HasPrefix(ciphertext, prefix) {
		t.Fatal("Seal: result should start with dst prefix")
	}

	// Strip prefix, Open with non-nil dst prefix
	ct := ciphertext[len(prefix):]
	outPrefix := []byte("OUT:")
	decrypted, err := a.Open(outPrefix, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.HasPrefix(decrypted, outPrefix) {
		t.Fatal("Open: result should start with dst prefix")
	}
	if !bytes.Equal(decrypted[len(outPrefix):], plaintext) {
		t.Fatalf("Open: got %q, want %q", decrypted[len(outPrefix):], plaintext)
	}
}
