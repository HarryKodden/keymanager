package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MemoryKeyManager is a simple in-memory KeyManager (ephemeral)
type MemoryKeyManager struct {
	keys map[string]*ecdsa.PrivateKey
	meta map[string]*KeyMetadata
	mu   sync.RWMutex
}

func NewMemoryKeyManager() *MemoryKeyManager {
	return &MemoryKeyManager{keys: make(map[string]*ecdsa.PrivateKey), meta: make(map[string]*KeyMetadata)}
}

func (m *MemoryKeyManager) LoadKeys() error { return nil }

func (m *MemoryKeyManager) GetSigningKey(kid string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if k, ok := m.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("signing key %s not found", kid)
}

func (m *MemoryKeyManager) GetJWKS() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := []interface{}{}
	for kid, pk := range m.keys {
		x := base64.RawURLEncoding.EncodeToString(pk.PublicKey.X.Bytes())
		y := base64.RawURLEncoding.EncodeToString(pk.PublicKey.Y.Bytes())
		keys = append(keys, map[string]interface{}{"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256", "x": x, "y": y})
	}
	return map[string]interface{}{"keys": keys}, nil
}

func (m *MemoryKeyManager) Sign(kid string, payload []byte) ([]byte, error) {
	m.mu.RLock()
	k, ok := m.keys[kid]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key %s not found", kid)
	}
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		return nil, err
	}
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	return sig, nil
}

func (m *MemoryKeyManager) GenerateKey(name string, kty string, alg string) (*KeyMetadata, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405Z"))
	m.mu.Lock()
	m.keys[kid] = priv
	m.meta[kid] = &KeyMetadata{Kid: kid, Kty: "EC", Alg: "ES256", Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}
	m.mu.Unlock()
	return m.meta[kid], nil
}

func (m *MemoryKeyManager) RotateKey(name string) (*KeyMetadata, error) {
	return m.GenerateKey(name, "EC", "ES256")
}

func (m *MemoryKeyManager) ListKeys() ([]*KeyMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*KeyMetadata{}
	for _, md := range m.meta {
		out = append(out, md)
	}
	return out, nil
}

func (m *MemoryKeyManager) RevokeKey(kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if md, ok := m.meta[kid]; ok {
		md.Status = KeyStatusRetired
		return nil
	}
	return fmt.Errorf("unknown key %s", kid)
}

func (m *MemoryKeyManager) SignKeyAnnouncement(newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error) {
	header := map[string]interface{}{"alg": "ES256", "kid": oldKid, "typ": "JWT"}
	now := time.Now().UTC()
	payload := map[string]interface{}{"iss": iss, "iat": now.Unix(), "exp": now.Add(exp).Unix(), "jwks": map[string]interface{}{"keys": []interface{}{newJWK}}}
	hb, _ := jsonMarshal(header)
	pb, _ := jsonMarshal(payload)
	hdrEnc := base64.RawURLEncoding.EncodeToString(hb)
	pldEnc := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := hdrEnc + "." + pldEnc
	sig, err := m.Sign(oldKid, []byte(signingInput))
	if err != nil {
		return "", err
	}
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigEnc, nil
}

func (m *MemoryKeyManager) ImportKey(name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error) {
	return nil, fmt.Errorf("ImportKey not implemented for MemoryKeyManager")
}

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
