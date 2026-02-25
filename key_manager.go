package keymanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"strconv"
	"time"
)

// KeyStatus indicates lifecycle of a key
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusStandby KeyStatus = "standby"
	KeyStatusRetired KeyStatus = "retired"
)

// typed errors
var (
	ErrKeyNotFound          = errors.New("key not found")
	ErrKeyNotActive         = errors.New("key not active")
	ErrUnsupportedOperation = errors.New("operation not supported")
)

// KeyMetadata holds information about a single key
type KeyMetadata struct {
	Kid       string    `json:"kid"`
	Kty       string    `json:"kty"`
	Use       string    `json:"use,omitempty"`
	Alg       string    `json:"alg,omitempty"`
	Status    KeyStatus `json:"status,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// KeyManager is an abstraction over key storage and signing operations
type KeyManager interface {
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
	Sign(ctx context.Context, kid string, payload []byte) ([]byte, error)
	GenerateKey(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error)
	RotateKey(ctx context.Context, name string) (*KeyMetadata, error)
	ListKeys(ctx context.Context) ([]*KeyMetadata, error)
	RevokeKey(ctx context.Context, kid string) error
	KeyStatus(ctx context.Context, kid string) (KeyStatus, error)
}

// AdvancedKeyManager extends KeyManager with higher-level operations used for
// rolling keys, announcements, importing backups and lifecycle management.
type AdvancedKeyManager interface {
	KeyManager
	LoadKeys(ctx context.Context) error
	GetSigningKey(ctx context.Context, kid string) (interface{}, error)
	ActivateKey(ctx context.Context, kid string) error
	DeactivateKey(ctx context.Context, kid string) error
	GenerateAndActivate(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error)
	SignKeyAnnouncement(ctx context.Context, newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error)
	ImportKey(ctx context.Context, name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error)
}

// DefaultRSABits is the default RSA key size used for GeneratePrivateKey.
var DefaultRSABits = 2048

func init() {
	if v := os.Getenv("KEYMANAGER_RSA_BITS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1024 {
			DefaultRSABits = n
		}
	}
}

// GeneratePrivateKey generates a private key for the given kty.
// If rsaBits <= 0, DefaultRSABits is used.
func GeneratePrivateKey(kty string, rsaBits int) (interface{}, error) {
	if kty == "RSA" {
		if rsaBits <= 0 {
			rsaBits = DefaultRSABits
		}
		return rsa.GenerateKey(rand.Reader, rsaBits)
	}
	// default to P-256
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
