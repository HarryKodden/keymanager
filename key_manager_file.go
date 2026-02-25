package keymanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileKeyManager stores encrypted private keys on disk under a directory.
type FileKeyManager struct {
	dir        string
	passphrase string
	mu         sync.RWMutex
	keys       map[string]interface{}
	meta       map[string]*KeyMetadata
}

func NewFileKeyManager(dir string, passphrase string) *FileKeyManager {
	if dir == "" {
		dir = "./keys"
	}
	log.Printf("[KEYMANAGER][FILE] loading keys from %s", dir)

	return &FileKeyManager{dir: dir, passphrase: passphrase, keys: make(map[string]interface{}), meta: make(map[string]*KeyMetadata)}
}

type fileKeyBlob struct {
	Kid       string    `json:"kid"`
	Kty       string    `json:"kty"`
	Alg       string    `json:"alg"`
	Status    KeyStatus `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Nonce     string    `json:"nonce"`
	Data      string    `json:"data"`
}

func deriveKey(pass string) []byte {
	h := sha256.Sum256([]byte(pass))
	return h[:]
}

func zeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

func (f *FileKeyManager) LoadKeys(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	files, err := ioutil.ReadDir(f.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		if !strings.HasSuffix(fi.Name(), ".key.json") {
			continue
		}
		full := filepath.Join(f.dir, fi.Name())
		b, err := ioutil.ReadFile(full)
		if err != nil {
			continue
		}
		var blob fileKeyBlob
		if err := json.Unmarshal(b, &blob); err != nil {
			continue
		}
		key := deriveKey(f.passphrase)
		nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
		if err != nil {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(blob.Data)
		if err != nil {
			continue
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			// zero ciphertext/nonce on error
			zeroBytes(ct)
			zeroBytes(nonce)
			continue
		}
		var privIfc interface{}
		// Try PKCS#8 first, then fall back to PKCS#1 or EC private key formats
		if p, err := x509.ParsePKCS8PrivateKey(plain); err == nil {
			privIfc = p
		} else if p, err := x509.ParsePKCS1PrivateKey(plain); err == nil {
			privIfc = p
		} else if p, err := x509.ParseECPrivateKey(plain); err == nil {
			privIfc = p
		} else {
			// zero plaintext and continue
			zeroBytes(plain)
			zeroBytes(ct)
			zeroBytes(nonce)
			continue
		}
		// zero sensitive buffers after parsing
		zeroBytes(plain)
		zeroBytes(ct)
		zeroBytes(nonce)
		f.keys[blob.Kid] = privIfc
		f.meta[blob.Kid] = &KeyMetadata{Kid: blob.Kid, Kty: blob.Kty, Alg: blob.Alg, Status: blob.Status, CreatedAt: blob.CreatedAt}
	}
	return nil
}

func (f *FileKeyManager) saveKeyToDisk(kid string, priv interface{}, meta *KeyMetadata) error {
	if err := os.MkdirAll(f.dir, 0700); err != nil {
		return err
	}
	var der []byte
	var err error
	// Marshal to PKCS#8 for compatibility across key types
	der, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	key := deriveKey(f.passphrase)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(der)
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(der)
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		zeroBytes(der)
		return err
	}
	ct := gcm.Seal(nil, nonce, der, nil)
	blob := fileKeyBlob{Kid: kid, Kty: meta.Kty, Alg: meta.Alg, Status: meta.Status, CreatedAt: meta.CreatedAt, Nonce: base64.StdEncoding.EncodeToString(nonce), Data: base64.StdEncoding.EncodeToString(ct)}
	out, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		zeroBytes(der)
		zeroBytes(ct)
		zeroBytes(nonce)
		return err
	}
	fname := filepath.Join(f.dir, kid+".key.json")
	if err := ioutil.WriteFile(fname, out, 0600); err != nil {
		zeroBytes(der)
		zeroBytes(ct)
		zeroBytes(nonce)
		return err
	}
	// enforce file perms
	_ = os.Chmod(fname, 0600)

	// zero sensitive buffers as soon as possible
	zeroBytes(der)
	zeroBytes(ct)
	zeroBytes(nonce)
	log.Printf("[KEYMANAGER][FILE] saved key %s to %s", kid, fname)
	return nil
}

func (f *FileKeyManager) GetSigningKey(ctx context.Context, kid string) (interface{}, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if md, ok := f.meta[kid]; ok {
		if md.Status != KeyStatusActive {
			return nil, ErrKeyNotActive
		}
		if k, ok := f.keys[kid]; ok {
			return k, nil
		}
	}
	return nil, ErrKeyNotFound
}

func (f *FileKeyManager) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	jwks, err := JWKSFromPrivateKeyMap(f.keys)
	if err != nil {
		log.Printf("[KEYMANAGER][FILE] error generating JWKS: %v", err)
		return nil, err
	}
	log.Printf("[KEYMANAGER][FILE] returning JWKS with %d keys", len(jwks["keys"].([]interface{})))
	return jwks, nil
}

func (f *FileKeyManager) Sign(ctx context.Context, kid string, payload []byte) ([]byte, error) {
	log.Printf("[KEYMANAGER][FILE] Sign requested using kid=%s", kid)
	si, err := f.GetSigningKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	sig, err := SignPayload(si, payload)
	if err != nil {
		return nil, err
	}
	log.Printf("[KEYMANAGER][FILE] Sign completed for kid=%s", kid)
	return sig, nil
}

func (f *FileKeyManager) GenerateKey(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error) {
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
	if alg == "" {
		if strings.EqualFold(kty, "RSA") {
			alg = "RS256"
		} else {
			alg = "ES256"
		}
	}
	kid := fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405Z"))
	if kty == "" {
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
	meta := &KeyMetadata{Kid: kid, Kty: kty, Alg: alg, Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}
	f.mu.Lock()
	f.keys[kid] = privIfc
	f.meta[kid] = meta
	f.mu.Unlock()
	// persist
	if err := f.saveKeyToDisk(kid, privIfc, meta); err != nil {
		return nil, err
	}
	log.Printf("[KEYMANAGER][FILE] generated key %s (kty=%s alg=%s)", kid, kty, alg)
	return meta, nil
}

func (f *FileKeyManager) RotateKey(ctx context.Context, name string) (*KeyMetadata, error) {
	return f.GenerateKey(ctx, name, "EC", "ES256")
}

func (f *FileKeyManager) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []*KeyMetadata{}
	for _, md := range f.meta {
		out = append(out, md)
	}
	log.Printf("[KEYMANAGER][FILE] listing %d keys", len(out))
	return out, nil
}

func (f *FileKeyManager) RevokeKey(ctx context.Context, kid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if md, ok := f.meta[kid]; ok {
		md.Status = KeyStatusRetired
		if priv, ok2 := f.keys[kid]; ok2 {
			return f.saveKeyToDisk(kid, priv, md)
		}
		return nil
	}
	return fmt.Errorf("unknown key %s", kid)
}

func (f *FileKeyManager) KeyStatus(ctx context.Context, kid string) (KeyStatus, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if md, ok := f.meta[kid]; ok {
		return md.Status, nil
	}
	return "", ErrKeyNotFound
}

func (f *FileKeyManager) SignKeyAnnouncement(ctx context.Context, newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error) {
	header := map[string]interface{}{"alg": "ES256", "kid": oldKid, "typ": "JWT"}
	now := time.Now().UTC()
	payload := map[string]interface{}{"iss": iss, "iat": now.Unix(), "exp": now.Add(exp).Unix(), "jwks": map[string]interface{}{"keys": []interface{}{newJWK}}}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hdrEnc := base64.RawURLEncoding.EncodeToString(hb)
	pldEnc := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := hdrEnc + "." + pldEnc
	sig, err := f.Sign(ctx, oldKid, []byte(signingInput))
	if err != nil {
		return "", err
	}
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigEnc, nil
}

func (f *FileKeyManager) ImportKey(ctx context.Context, name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	var privIfc interface{}
	var kty string
	// Try PKCS#8 (PRIVATE KEY) first, then fall back to RSA/EC specific formats
	if p, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		privIfc = p
		switch p.(type) {
		case *rsa.PrivateKey:
			kty = "RSA"
		default:
			kty = "EC"
		}
	} else if strings.Contains(block.Type, "RSA") {
		p, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		privIfc = p
		kty = "RSA"
	} else {
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		privIfc = p
		kty = "EC"
	}
	kid := fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405Z"))
	alg := ""
	if kty == "RSA" {
		alg = "RS256"
	} else {
		alg = "ES256"
	}
	meta := &KeyMetadata{Kid: kid, Kty: kty, Alg: alg, Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}
	f.mu.Lock()
	f.keys[kid] = privIfc
	f.meta[kid] = meta
	f.mu.Unlock()
	if err := f.saveKeyToDisk(kid, privIfc, meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func (f *FileKeyManager) ActivateKey(ctx context.Context, kid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	md, ok := f.meta[kid]
	if !ok {
		return ErrKeyNotFound
	}
	md.Status = KeyStatusActive
	if priv, ok2 := f.keys[kid]; ok2 {
		if err := f.saveKeyToDisk(kid, priv, md); err != nil {
			return err
		}
	}
	log.Printf("[KEYMANAGER][FILE] activated key %s", kid)
	return nil
}

func (f *FileKeyManager) DeactivateKey(ctx context.Context, kid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	md, ok := f.meta[kid]
	if !ok {
		return ErrKeyNotFound
	}
	md.Status = KeyStatusStandby
	if priv, ok2 := f.keys[kid]; ok2 {
		if err := f.saveKeyToDisk(kid, priv, md); err != nil {
			return err
		}
	}
	log.Printf("[KEYMANAGER][FILE] deactivated key %s", kid)
	return nil
}

func (f *FileKeyManager) GenerateAndActivate(ctx context.Context, name string, kty string, alg string) (*KeyMetadata, error) {
	md, err := f.GenerateKey(ctx, name, kty, alg)
	if err != nil {
		return nil, err
	}
	if err := f.ActivateKey(ctx, md.Kid); err != nil {
		return nil, err
	}
	return md, nil
}
