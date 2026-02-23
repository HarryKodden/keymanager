package keymanager

import "time"

// KeyStatus indicates lifecycle of a key
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusStandby KeyStatus = "standby"
	KeyStatusRetired KeyStatus = "retired"
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
	GetJWKS() (map[string]interface{}, error)
	Sign(kid string, payload []byte) ([]byte, error)
	GenerateKey(name string, kty string, alg string) (*KeyMetadata, error)
	RotateKey(name string) (*KeyMetadata, error)
	ListKeys() ([]*KeyMetadata, error)
	RevokeKey(kid string) error
}

// AdvancedKeyManager extends KeyManager with higher-level operations used for
// rolling keys, announcements, and importing backups.
type AdvancedKeyManager interface {
	KeyManager
	LoadKeys() error
	GetSigningKey(kid string) (interface{}, error)
	SignKeyAnnouncement(newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error)
	ImportKey(name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error)
}
