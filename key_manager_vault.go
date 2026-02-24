package keymanager

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
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
	log.Printf("[KEYMANAGER][VAULT] initialized vault key manager (mount=%s)", transitMount)
	return &VaultKeyManager{client: client, transitMount: transitMount}
}

func base64URLNoPad(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b)
	return s
}

func (v *VaultKeyManager) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
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

	log.Printf("[KEYMANAGER][VAULT] fetching JWKS for %d keys", len(keys))
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
		kid := fmt.Sprintf("%s-%v", name, sec.Data["min_encryption_version"])
		if jwk, err := jwkFromPublicKey(kid, pubIfc, ""); err == nil {
			jwkKeys = append(jwkKeys, jwk)
		}
	}

	return map[string]interface{}{"keys": jwkKeys}, nil
}

func (v *VaultKeyManager) Sign(ctx context.Context, kid string, payload []byte) ([]byte, error) {
	log.Printf("[KEYMANAGER][VAULT] Sign requested for kid=%s", kid)
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
	// convert DER ECDSA signature to raw r||s (ECDSADERToRaw zeros DER input)
	sig, err := ECDSADERToRaw(der, 32)
	if err != nil {
		// zero der on error
		for i := range der {
			der[i] = 0
		}
		return nil, fmt.Errorf("failed to convert ecdsa der->raw: %w", err)
	}
	log.Printf("[KEYMANAGER][VAULT] Sign completed for kid=%s via vault key=%s", kid, name)
	return sig, nil
}

func (v *VaultKeyManager) GenerateKey(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error) {
	vtype := "ecdsa-p256"
	if strings.EqualFold(kty, "RSA") {
		vtype = "rsa-2048"
	}
	data := map[string]interface{}{"type": vtype}
	_, err := v.client.Logical().Write(fmt.Sprintf("%s/keys/%s", v.transitMount, name), data)
	if err != nil {
		return nil, err
	}
	if kty == "" {
		kty = "EC"
	}
	if alg == "" {
		alg = "ES256"
	}
	log.Printf("[KEYMANAGER][VAULT] generated key %s (type=%s kty=%s alg=%s)", name, vtype, kty, alg)
	return &KeyMetadata{Kid: name, Kty: kty, Alg: alg, Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}, nil
}

func (v *VaultKeyManager) RotateKey(ctx context.Context, name string) (*KeyMetadata, error) {
	_, err := v.client.Logical().Write(fmt.Sprintf("%s/keys/%s/rotate", v.transitMount, name), nil)
	if err != nil {
		return nil, err
	}
	log.Printf("[KEYMANAGER][VAULT] rotated key %s", name)
	return &KeyMetadata{Kid: name, Status: KeyStatusActive, CreatedAt: time.Now().UTC()}, nil
}

func (v *VaultKeyManager) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
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
	log.Printf("[KEYMANAGER][VAULT] listing %d keys", len(out))
	return out, nil
}

func (v *VaultKeyManager) RevokeKey(ctx context.Context, kid string) error {
	name := kid
	if idx := strings.Index(kid, "-"); idx != -1 {
		name = kid[:idx]
	}
	log.Printf("[KEYMANAGER][VAULT] revoking key %s (vault name=%s)", kid, name)
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

func (v *VaultKeyManager) LoadKeys(ctx context.Context) error { return nil }

func (v *VaultKeyManager) GetSigningKey(ctx context.Context, kid string) (interface{}, error) {
	name := kid
	if idx := strings.Index(kid, "-"); idx != -1 {
		name = kid[:idx]
	}
	log.Printf("[KEYMANAGER][VAULT] GetSigningKey lookup for kid=%s -> vault name=%s", kid, name)
	sec, err := v.client.Logical().Read(fmt.Sprintf("%s/keys/%s", v.transitMount, name))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, ErrKeyNotFound
	}
	minVer := sec.Data["min_encryption_version"]
	expectedKid := fmt.Sprintf("%s-%v", name, minVer)
	if expectedKid != kid {
		return nil, ErrKeyNotActive
	}
	return name, nil
}

func (v *VaultKeyManager) ActivateKey(ctx context.Context, kid string) error {
	name := kid
	if idx := strings.Index(kid, "-"); idx != -1 {
		name = kid[:idx]
	}
	// rotate to create an active version
	_, err := v.RotateKey(ctx, name)
	return err
}

func (v *VaultKeyManager) DeactivateKey(ctx context.Context, kid string) error {
	// Vault transit doesn't provide a simple "deactivate" API; document as unsupported
	return ErrUnsupportedOperation
}

func (v *VaultKeyManager) GenerateAndActivate(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error) {
	md, err := v.GenerateKey(ctx, name, kty, alg)
	if err != nil {
		return nil, err
	}
	// Activate by rotating/creating an active version
	if err := v.ActivateKey(ctx, md.Kid); err != nil {
		return nil, err
	}
	return md, nil
}

func (v *VaultKeyManager) SignKeyAnnouncement(ctx context.Context, newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error) {
	log.Printf("[KEYMANAGER][VAULT] signing key announcement oldKid=%s", oldKid)
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
	sig, err := v.Sign(ctx, oldKid, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign announcement via Vault: %w", err)
	}
	sigEnc := base64URLNoPad(sig)
	return fmt.Sprintf("%s.%s", signingInput, sigEnc), nil
}

func (v *VaultKeyManager) ImportKey(ctx context.Context, name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error) {
	log.Printf("[KEYMANAGER][VAULT] ImportKey not implemented for VaultKeyManager")
	return nil, fmt.Errorf("ImportKey not implemented for VaultKeyManager")
}
