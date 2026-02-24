package keymanager

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// MemoryKeyManager is a simple in-memory KeyManager (ephemeral)
type MemoryKeyManager struct {
	keys map[string]interface{}
	meta map[string]*KeyMetadata
	mu   sync.RWMutex
}

func NewMemoryKeyManager() *MemoryKeyManager {
	log.Printf("[KEYMANAGER][MEMORY] initialized ephemeral memory key manager")
	return &MemoryKeyManager{keys: make(map[string]interface{}), meta: make(map[string]*KeyMetadata)}
}

func (m *MemoryKeyManager) LoadKeys(ctx context.Context) error { return nil }

func (m *MemoryKeyManager) GetSigningKey(ctx context.Context, kid string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if md, ok := m.meta[kid]; ok {
		if md.Status != KeyStatusActive {
			log.Printf("[KEYMANAGER][MEMORY] signing key not active: %s status=%s", kid, md.Status)
			return nil, ErrKeyNotActive
		}
		if k, ok := m.keys[kid]; ok {
			return k, nil
		}
	}
	log.Printf("[KEYMANAGER][MEMORY] signing key not found: %s", kid)
	return nil, ErrKeyNotFound
}

func (m *MemoryKeyManager) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	jwks, err := JWKSFromPrivateKeyMap(m.keys)
	if err != nil {
		return nil, err
	}
	log.Printf("[KEYMANAGER][MEMORY] returning JWKS with %d keys", len(jwks["keys"].([]interface{})))
	return jwks, nil
}

func (m *MemoryKeyManager) Sign(ctx context.Context, kid string, payload []byte) ([]byte, error) {
	log.Printf("[KEYMANAGER][MEMORY] Sign requested using kid=%s", kid)
	si, err := m.GetSigningKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	sig, err := SignPayload(si, payload)
	if err != nil {
		return nil, err
	}
	log.Printf("[KEYMANAGER][MEMORY] Sign completed for kid=%s", kid)
	return sig, nil
}

func (m *MemoryKeyManager) GenerateKey(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error) {
	var privIfc interface{}
	var err error
	if kty == "" {
		privIfc, err = GeneratePrivateKey("", 0)
	} else {
		privIfc, err = GeneratePrivateKey(kty, 0)
	}
	if err != nil {
		return nil, err
	}
	kid := fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405Z"))
	if kty == "" {
		// choose default based on generated key
		switch privIfc.(type) {
		case *rsa.PrivateKey:
			kty = "RSA"
		default:
			kty = "EC"
		}
	}
	if alg == "" {
		if kty == "RSA" {
			alg = "RS256"
		} else {
			alg = "ES256"
		}
	}
	m.mu.Lock()
	m.keys[kid] = privIfc
	m.meta[kid] = &KeyMetadata{Kid: kid, Kty: kty, Alg: alg, Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}
	m.mu.Unlock()
	log.Printf("[KEYMANAGER][MEMORY] generated key %s (kty=%s alg=%s)", kid, kty, alg)
	return m.meta[kid], nil
}

func (m *MemoryKeyManager) ActivateKey(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if md, ok := m.meta[kid]; ok {
		md.Status = KeyStatusActive
		log.Printf("[KEYMANAGER][MEMORY] activated key %s", kid)
		return nil
	}
	return ErrKeyNotFound
}

func (m *MemoryKeyManager) DeactivateKey(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if md, ok := m.meta[kid]; ok {
		md.Status = KeyStatusStandby
		log.Printf("[KEYMANAGER][MEMORY] deactivated key %s", kid)
		return nil
	}
	return ErrKeyNotFound
}

func (m *MemoryKeyManager) GenerateAndActivate(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error) {
	md, err := m.GenerateKey(ctx, name, kty, alg)
	if err != nil {
		return nil, err
	}
	if err := m.ActivateKey(ctx, md.Kid); err != nil {
		return nil, err
	}
	return md, nil
}

func (m *MemoryKeyManager) RotateKey(ctx context.Context, name string) (*KeyMetadata, error) {
	return m.GenerateKey(ctx, name, "EC", "ES256")
}

func (m *MemoryKeyManager) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*KeyMetadata{}
	for _, md := range m.meta {
		out = append(out, md)
	}
	log.Printf("[KEYMANAGER][MEMORY] listing %d keys", len(out))
	return out, nil
}

func (m *MemoryKeyManager) RevokeKey(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if md, ok := m.meta[kid]; ok {
		md.Status = KeyStatusRetired
		log.Printf("[KEYMANAGER][MEMORY] revoked key %s", kid)
		return nil
	}
	log.Printf("[KEYMANAGER][MEMORY] revoke unknown key %s", kid)
	return fmt.Errorf("unknown key %s", kid)
}

func (m *MemoryKeyManager) SignKeyAnnouncement(ctx context.Context, newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error) {
	log.Printf("[KEYMANAGER][MEMORY] signing key announcement oldKid=%s", oldKid)
	header := map[string]interface{}{"alg": "ES256", "kid": oldKid, "typ": "JWT"}
	now := time.Now().UTC()
	payload := map[string]interface{}{"iss": iss, "iat": now.Unix(), "exp": now.Add(exp).Unix(), "jwks": map[string]interface{}{"keys": []interface{}{newJWK}}}
	hb, _ := jsonMarshal(header)
	pb, _ := jsonMarshal(payload)
	hdrEnc := base64.RawURLEncoding.EncodeToString(hb)
	pldEnc := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := hdrEnc + "." + pldEnc
	sig, err := m.Sign(ctx, oldKid, []byte(signingInput))
	if err != nil {
		return "", err
	}
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigEnc, nil
}

func (m *MemoryKeyManager) ImportKey(ctx context.Context, name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error) {
	log.Printf("[KEYMANAGER][MEMORY] ImportKey not implemented for MemoryKeyManager")
	return nil, fmt.Errorf("ImportKey not implemented for MemoryKeyManager")
}

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
