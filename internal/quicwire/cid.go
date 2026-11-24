// Package quicwire implements the small subset of QUIC wire formatting and
// the authenticated backend-routable Connection ID used by the load balancer.
package quicwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// CIDLength is the agreed short-header Destination Connection ID length.
// QUIC permits up to 20 bytes; this layout uses all 20 bytes.
const CIDLength = 20

const (
	keyLabelEnc    = "cidlb/cid-encryption/v1"
	keyLabelMAC    = "cidlb/cid-authentication/v1"
	keyLabelMaster = "cidlb/shared-secret/v1"
)

var (
	ErrBadCIDLength = errors.New("cid: invalid connection id length")
	ErrUnknownKeyID = errors.New("cid: unknown key identifier")
	ErrBadMAC       = errors.New("cid: authentication tag mismatch")
)

// CIDCodec creates and validates backend-identity Connection IDs.
//
// Wire layout:
//
//	0       1          8             12                20
//	+-------+----------+-------------+-----------------+
//	| keyID | nonce(7) | backend(4)  | truncated MAC(8)|
//	+-------+----------+-------------+-----------------+
//
// The backend field is encrypted with AES-CTR and the first 12 bytes are
// authenticated with HMAC-SHA256 truncated to 8 bytes. The keyID identifies
// the key generation, not a backend.
type CIDCodec struct {
	keyID  byte
	encKey []byte
	macKey []byte
}

// NewCIDCodec derives separate encryption and authentication keys from the
// shared LB/backend secret.
func NewCIDCodec(sharedSecret string, keyID byte) *CIDCodec {
	master := hmacSHA256([]byte(sharedSecret), []byte(keyLabelMaster))
	return &CIDCodec{
		keyID:  keyID,
		encKey: hmacSHA256(master, []byte(keyLabelEnc)),
		macKey: hmacSHA256(master, []byte(keyLabelMAC)),
	}
}

// KeyID returns the non-secret key generation byte.
func (c *CIDCodec) KeyID() byte { return c.keyID }

// Encode produces an authenticated CID for backend. The nonce must not repeat
// for CIDs created with this key; the simulator uses its deterministic RNG.
func (c *CIDCodec) Encode(backend uint32, nonce [7]byte) ([]byte, error) {
	raw := make([]byte, CIDLength)
	raw[0] = c.keyID
	copy(raw[1:8], nonce[:])
	binary.BigEndian.PutUint32(raw[8:12], backend)

	block, err := aes.NewCipher(c.encKey)
	if err != nil {
		return nil, err
	}
	// 16-byte CTR IV. The keyID and seven-byte nonce make simulated CIDs
	// distinct; the remaining counter bytes start at zero.
	iv := make([]byte, aes.BlockSize)
	iv[0] = c.keyID
	copy(iv[1:8], nonce[:])
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(raw[8:12], raw[8:12])

	tag := c.mac(raw[:12])
	copy(raw[12:20], tag[:8])
	return raw, nil
}

// Decode verifies the CID before decrypting its backend identity.
func (c *CIDCodec) Decode(cid []byte) (uint32, error) {
	if len(cid) != CIDLength {
		return 0, ErrBadCIDLength
	}
	if cid[0] != c.keyID {
		return 0, ErrUnknownKeyID
	}
	want := c.mac(cid[:12])
	if subtle.ConstantTimeCompare(cid[12:20], want[:8]) != 1 {
		return 0, ErrBadMAC
	}

	block, err := aes.NewCipher(c.encKey)
	if err != nil {
		return 0, err
	}
	iv := make([]byte, aes.BlockSize)
	iv[0] = c.keyID
	copy(iv[1:8], cid[1:8])
	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, 4)
	stream.XORKeyStream(decrypted, cid[8:12])
	return binary.BigEndian.Uint32(decrypted), nil
}

func (c *CIDCodec) mac(data []byte) [32]byte {
	m := hmac.New(sha256.New, c.macKey)
	_, _ = m.Write(data)
	var sum [32]byte
	copy(sum[:], m.Sum(nil))
	return sum
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(data)
	return m.Sum(nil)
}
