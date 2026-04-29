/* aes_handles.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package handles

import (
	"fmt"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// AesGcmAEAD implements crypto/cipher.AEAD using wolfCrypt AES-256-GCM.
// Create one with NewAesGcmAEAD.
type AesGcmAEAD struct {
	key [wolfSSL.AES_256_KEY_SIZE]byte
}

// NewAesGcmAEAD returns an AesGcmAEAD keyed with a 32-byte AES-256 key.
func NewAesGcmAEAD(key [wolfSSL.AES_256_KEY_SIZE]byte) *AesGcmAEAD {
	return &AesGcmAEAD{key: key}
}

func (a *AesGcmAEAD) NonceSize() int { return wolfSSL.AES_IV_SIZE }
func (a *AesGcmAEAD) Overhead() int  { return wolfSSL.AES_BLOCK_SIZE }

// Seal encrypts and authenticates plaintext, appending the result to dst.
// The ciphertext and tag are concatenated: dst || ct || tag.
func (a *AesGcmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	aes := wolfSSL.Wc_AesAllocAligned()
	wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_AesGcmSetKey(aes, a.key[:], wolfSSL.AES_256_KEY_SIZE)
	defer func() {
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)
	}()

	ct := make([]byte, len(plaintext))
	var tag [wolfSSL.AES_BLOCK_SIZE]byte
	wolfSSL.Wc_AesGcmEncrypt(aes, ct, plaintext, nonce, tag[:], additionalData)

	out := append(dst, ct...)
	out = append(out, tag[:]...)
	return out
}

// Open decrypts and verifies ciphertext (which must include the appended
// tag), appending the plaintext to dst.
func (a *AesGcmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < wolfSSL.AES_BLOCK_SIZE {
		return nil, fmt.Errorf("wolfSSL: ciphertext too short (%d bytes)", len(ciphertext))
	}
	aes := wolfSSL.Wc_AesAllocAligned()
	wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_AesGcmSetKey(aes, a.key[:], wolfSSL.AES_256_KEY_SIZE)
	defer func() {
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)
	}()

	ctLen := len(ciphertext) - wolfSSL.AES_BLOCK_SIZE
	ct := ciphertext[:ctLen]
	tag := ciphertext[ctLen:]

	plaintext := make([]byte, ctLen)
	ret := wolfSSL.Wc_AesGcmDecrypt(aes, plaintext, ct, nonce, tag, additionalData)
	if ret != 0 {
		return nil, fmt.Errorf("wolfSSL: AES-GCM decrypt failed: %d", ret)
	}
	return append(dst, plaintext...), nil
}
