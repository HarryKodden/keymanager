package keymanager

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
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
		// Vault returns public keys nested under sec.Data["keys"][version].public_key
		if keysRaw, ok := sec.Data["keys"].(map[string]interface{}); ok {
			for ver, ventry := range keysRaw {
				if entryMap, ok := ventry.(map[string]interface{}); ok {
					pubRaw, _ := entryMap["public_key"].(string)
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
					kid := fmt.Sprintf("%s-%s", name, ver)
					if jwk, err := jwkFromPublicKey(kid, pubIfc, ""); err == nil {
						jwkKeys = append(jwkKeys, jwk)
					}
				}
			}
		}
		// fall back: some Vault versions may expose public_key at top-level
		if pubRaw, _ := sec.Data["public_key"].(string); pubRaw != "" {
			block, _ := pem.Decode([]byte(pubRaw))
			if block != nil {
				if pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
					// try to derive a reasonable kid using latest_version if present
					if lv, ok := sec.Data["latest_version"]; ok {
						kid := fmt.Sprintf("%s-%v", name, lv)
						if jwk, err := jwkFromPublicKey(kid, pubIfc, ""); err == nil {
							jwkKeys = append(jwkKeys, jwk)
						}
					} else {
						kid := name
						if jwk, err := jwkFromPublicKey(kid, pubIfc, ""); err == nil {
							jwkKeys = append(jwkKeys, jwk)
						}
					}
				}
			}
		}
	}

	return map[string]interface{}{"keys": jwkKeys}, nil
}

func (v *VaultKeyManager) Sign(ctx context.Context, kid string, payload []byte) ([]byte, error) {
	log.Printf("[KEYMANAGER][VAULT] Sign requested for kid=%s", kid)
	name, sec, err := v.resolveVaultName(kid)
	if err != nil {
		return nil, err
	}
	// Vault transit expects the `input` to be the raw bytes to sign encoded
	// in base64; to match local signing (which hashes the input first), send
	// the SHA-256 digest of the payload so Vault signs the digest directly.
	h := sha256.Sum256(payload)
	input := base64.StdEncoding.EncodeToString(h[:])
	// mark the input as already hashed so Vault won't hash it again
	data := map[string]interface{}{"input": input, "prehashed": true}
	// If kid includes a numeric version suffix (name-<ver>), request that exact
	// key version from Vault to ensure the signature matches the JWKS entry.
	if idx := strings.LastIndex(kid, "-"); idx != -1 && idx+1 < len(kid) {
		suffix := kid[idx+1:]
		if ver, verr := strconv.Atoi(suffix); verr == nil {
			// Only request a specific key_version if the key metadata contains that version
			if sec != nil && sec.Data != nil {
				if keysRaw, ok := sec.Data["keys"].(map[string]interface{}); ok {
					if _, ok2 := keysRaw[suffix]; ok2 {
						data["key_version"] = ver
					}
				}
			}
		}
	}
	path := fmt.Sprintf("%s/sign/%s", v.transitMount, name)
	resp, err := v.client.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("no signature returned from vault")
	}
	sigStr, _ := resp.Data["signature"].(string)
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
	// request exportable public key so Vault returns `public_key` in the key metadata
	data := map[string]interface{}{"type": vtype, "exportable": true}
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
	name, _, err := v.resolveVaultName(kid)
	if err != nil {
		return err
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
	name, sec, err := v.resolveVaultName(kid)
	log.Printf("[KEYMANAGER][VAULT] GetSigningKey lookup for kid=%s -> vault name=%s", kid, name)
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, ErrKeyNotFound
	}
	// If the kid includes a numeric version suffix (name-<ver>), ensure that
	// version exists in the key metadata. Otherwise, return the base name
	// if signing is supported for this key.
	if idx := strings.LastIndex(kid, "-"); idx != -1 && idx+1 < len(kid) {
		suffix := kid[idx+1:]
		if _, verr := strconv.Atoi(suffix); verr == nil {
			if keysRaw, ok := sec.Data["keys"].(map[string]interface{}); ok {
				if _, ok2 := keysRaw[suffix]; ok2 {
					return name, nil
				}
			}
			return nil, ErrKeyNotActive
		}
	}
	// No explicit version requested; accept name if signing supported
	if sup, ok := sec.Data["supports_signing"].(bool); ok && sup {
		return name, nil
	}
	return nil, ErrKeyNotActive
}

func (v *VaultKeyManager) ActivateKey(ctx context.Context, kid string) error {
	name, _, err := v.resolveVaultName(kid)
	if err != nil {
		return err
	}
	// rotate to create an active version
	_, err = v.RotateKey(ctx, name)
	return err
}

// resolveVaultName attempts to find the actual vault key name for a given
// `kid`. It first tries the exact `kid`; if not found and the `kid` ends
// with a numeric suffix (e.g. "name-<version>"), it will try the base
// name without the numeric suffix. Returns the resolved name and the
// secret read from Vault (if found).
func (v *VaultKeyManager) resolveVaultName(kid string) (string, *vault.Secret, error) {
	// try exact
	sec, err := v.client.Logical().Read(fmt.Sprintf("%s/keys/%s", v.transitMount, kid))
	if err != nil {
		return "", nil, err
	}
	if sec != nil && sec.Data != nil {
		return kid, sec, nil
	}
	// try stripping a numeric suffix
	if idx := strings.LastIndex(kid, "-"); idx != -1 && idx < len(kid)-1 {
		suffix := kid[idx+1:]
		if _, err := strconv.Atoi(suffix); err == nil {
			alt := kid[:idx]
			sec2, err2 := v.client.Logical().Read(fmt.Sprintf("%s/keys/%s", v.transitMount, alt))
			if err2 != nil {
				return "", nil, err2
			}
			if sec2 != nil && sec2.Data != nil {
				return alt, sec2, nil
			}
		}
	}
	return kid, nil, nil
}

// stripVersionSuffix returns the base key name by removing a numeric
// version suffix of the form "-<number>". If the suffix is not numeric
// the original name is returned unchanged. This preserves key names that
// legitimately contain hyphens.
func stripVersionSuffix(name string) string {
	if idx := strings.LastIndex(name, "-"); idx != -1 && idx < len(name)-1 {
		suffix := name[idx+1:]
		if _, err := strconv.Atoi(suffix); err == nil {
			return name[:idx]
		}
	}
	return name
}

func (v *VaultKeyManager) DeactivateKey(ctx context.Context, kid string) error {
	// Vault transit doesn't provide a simple "deactivate" API; document as unsupported
	return ErrUnsupportedOperation
}

func (v *VaultKeyManager) KeyStatus(ctx context.Context, kid string) (KeyStatus, error) {
	_, sec, err := v.resolveVaultName(kid)
	if err != nil {
		return "", err
	}
	if sec == nil || sec.Data == nil {
		return "", ErrKeyNotFound
	}
	// If signing is supported, consider the Vault key active
	if sup, ok := sec.Data["supports_signing"].(bool); ok && sup {
		return KeyStatusActive, nil
	}
	// otherwise return standby
	return KeyStatusStandby, nil
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
