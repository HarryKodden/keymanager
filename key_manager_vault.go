package keymanager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultKeyManager implements KeyManager using HashiCorp Vault transit
type VaultKeyManager struct {
	client       *vault.Client
	transitMount string
}

// NewVaultKeyManager creates a new VaultKeyManager. The caller must configure
// VAULT_ADDR and provide a token, or pass a configured vault.Client.
func NewVaultKeyManager(client *vault.Client, transitMount string) *VaultKeyManager {
	return &VaultKeyManager{client: client, transitMount: transitMount}
}

func base64URLNoPad(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b)
	return s
}

func (v *VaultKeyManager) GetJWKS() (map[string]interface{}, error) {
	secret, err := v.client.Logical().List(fmt.Sprintf("%s/keys", v.transitMount))
	if err != nil {
		return nil, err
	}

	var keys []string
	if secret != nil && secret.Data != nil {
		if raw, ok := secret.Data["keys"]; ok {
			if slice, ok := raw.([]interface{}); ok {
				for _, s := range slice {
					if name, ok := s.(string); ok {
						keys = append(keys, name)
					}
				}
			}
		}
	}

	jwkKeys := make([]map[string]interface{}, 0, len(keys))
	for _, name := range keys {
		sec, err := v.client.Logical().Read(fmt.Sprintf("%s/keys/%s", v.transitMount, name))
		if err != nil || sec == nil || sec.Data == nil {
			continue
		}
		pubRaw, _ := sec.Data["public_key"].(string)
		if pubRaw == "" {
			continue
		}
		block, _ := pem.Decode([]byte(pubRaw))
		if block == nil {
			continue
		}
		pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		switch pk := pubIfc.(type) {
		case *ecdsa.PublicKey:
			x := base64URLNoPad(pk.X.Bytes())
			y := base64URLNoPad(pk.Y.Bytes())
			kid := fmt.Sprintf("%s-%v", name, sec.Data["min_encryption_version"])
			jwk := map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"kid": kid,
				"use": "sig",
				"alg": "ES256",
				"x":   x,
				"y":   y,
			}
			jwkKeys = append(jwkKeys, jwk)
		default:
			continue
		}
	}

	return map[string]interface{}{"keys": jwkKeys}, nil
}

func (v *VaultKeyManager) Sign(kid string, payload []byte) ([]byte, error) {
	name := kid
	if idx := strings.Index(kid, "-"); idx != -1 {
		name = kid[:idx]
	}
	input := base64.StdEncoding.EncodeToString(payload)
	data := map[string]interface{}{"input": input}
	path := fmt.Sprintf("%s/sign/%s", v.transitMount, name)
	sec, err := v.client.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("no signature returned from vault")
	}
	sigStr, _ := sec.Data["signature"].(string)
	parts := strings.Split(sigStr, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected signature format from vault: %s", sigStr)
	}
	b64 := parts[len(parts)-1]
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault signature: %w", err)
	}
	var esig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &esig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ecdsa signature: %w", err)
	}
	keyBytes := 32
	rb := esig.R.Bytes()
	sb := esig.S.Bytes()
	sig := make([]byte, keyBytes*2)
	copy(sig[keyBytes-len(rb):keyBytes], rb)
	copy(sig[2*keyBytes-len(sb):], sb)
	return sig, nil
}

func (v *VaultKeyManager) GenerateKey(name string, kty string, alg string) (*KeyMetadata, error) {
	vtype := "ecdsa-p256"
	if strings.EqualFold(kty, "RSA") {
		vtype = "rsa-2048"
	}
	data := map[string]interface{}{"type": vtype}
	_, err := v.client.Logical().Write(fmt.Sprintf("%s/keys/%s", v.transitMount, name), data)
	if err != nil {
		return nil, err
	}
	return &KeyMetadata{Kid: name, Kty: kty, Alg: alg, Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}, nil
}

func (v *VaultKeyManager) RotateKey(name string) (*KeyMetadata, error) {
	_, err := v.client.Logical().Write(fmt.Sprintf("%s/keys/%s/rotate", v.transitMount, name), nil)
	if err != nil {
		return nil, err
	}
	return &KeyMetadata{Kid: name, Status: KeyStatusActive, CreatedAt: time.Now().UTC()}, nil
}

func (v *VaultKeyManager) ListKeys() ([]*KeyMetadata, error) {
	secret, err := v.client.Logical().List(fmt.Sprintf("%s/keys", v.transitMount))
	if err != nil {
		return nil, err
	}
	var out []*KeyMetadata
	if secret != nil && secret.Data != nil {
		if raw, ok := secret.Data["keys"]; ok {
			if slice, ok := raw.([]interface{}); ok {
				for _, s := range slice {
					if name, ok := s.(string); ok {
						out = append(out, &KeyMetadata{Kid: name})
					}
				}
			}
		}
	}
	return out, nil
}

func (v *VaultKeyManager) RevokeKey(kid string) error {
	name := kid
	if idx := strings.Index(kid, "-"); idx != -1 {
		name = kid[:idx]
	}
	cfgPath := fmt.Sprintf("%s/keys/%s/config", v.transitMount, name)
	_, _ = v.client.Logical().Write(cfgPath, map[string]interface{}{"deletion_allowed": true})
	delPath := fmt.Sprintf("%s/keys/%s", v.transitMount, name)
	if _, err := v.client.Logical().Delete(delPath); err != nil {
		return fmt.Errorf("failed to delete key %s from vault: %w", name, err)
	}
	return nil
}

func (v *VaultKeyManager) debugDump(i interface{}) string {
	b, _ := json.MarshalIndent(i, "", "  ")
	return string(b)
}

func (v *VaultKeyManager) LoadKeys() error { return nil }

func (v *VaultKeyManager) GetSigningKey(kid string) (interface{}, error) {
	name := kid
	if idx := strings.Index(kid, "-"); idx != -1 {
		name = kid[:idx]
	}
	return name, nil
}

func (v *VaultKeyManager) SignKeyAnnouncement(newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error) {
	header := map[string]interface{}{"alg": "ES256", "kid": oldKid, "typ": "JWT"}
	now := time.Now().UTC()
	payload := map[string]interface{}{"iss": iss, "iat": now.Unix(), "exp": now.Add(exp).Unix(), "jwks": map[string]interface{}{"keys": []interface{}{newJWK}}}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	hdrEnc := base64URLNoPad(hb)
	pldEnc := base64URLNoPad(pb)
	signingInput := fmt.Sprintf("%s.%s", hdrEnc, pldEnc)
	sig, err := v.Sign(oldKid, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign announcement via Vault: %w", err)
	}
	sigEnc := base64URLNoPad(sig)
	return fmt.Sprintf("%s.%s", signingInput, sigEnc), nil
}

func (v *VaultKeyManager) ImportKey(name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error) {
	return nil, fmt.Errorf("ImportKey not implemented for VaultKeyManager")
}
