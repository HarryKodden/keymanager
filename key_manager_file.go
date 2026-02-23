package keymanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
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
	keys       map[string]*ecdsa.PrivateKey
	meta       map[string]*KeyMetadata
}

func NewFileKeyManager(dir string, passphrase string) *FileKeyManager {
	if dir == "" {
		dir = "./keys"
	}
	return &FileKeyManager{dir: dir, passphrase: passphrase, keys: make(map[string]*ecdsa.PrivateKey), meta: make(map[string]*KeyMetadata)}
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

func (f *FileKeyManager) LoadKeys() error {
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
			continue
		}
		priv, err := x509.ParseECPrivateKey(plain)
		if err != nil {
			continue
		}
		f.keys[blob.Kid] = priv
		f.meta[blob.Kid] = &KeyMetadata{Kid: blob.Kid, Kty: blob.Kty, Alg: blob.Alg, Status: blob.Status, CreatedAt: blob.CreatedAt}
	}
	return nil
}

func (f *FileKeyManager) saveKeyToDisk(kid string, priv *ecdsa.PrivateKey, meta *KeyMetadata) error {
	if err := os.MkdirAll(f.dir, 0700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	key := deriveKey(f.passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, der, nil)
	blob := fileKeyBlob{Kid: kid, Kty: meta.Kty, Alg: meta.Alg, Status: meta.Status, CreatedAt: meta.CreatedAt, Nonce: base64.StdEncoding.EncodeToString(nonce), Data: base64.StdEncoding.EncodeToString(ct)}
	out, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return err
	}
	fname := filepath.Join(f.dir, kid+".key.json")
	return ioutil.WriteFile(fname, out, 0600)
}

func (f *FileKeyManager) GetSigningKey(kid string) (interface{}, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if k, ok := f.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("key %s not found", kid)
}

func (f *FileKeyManager) GetJWKS() (map[string]interface{}, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	keys := []interface{}{}
	for kid, pk := range f.keys {
		x := base64.RawURLEncoding.EncodeToString(pk.PublicKey.X.Bytes())
		y := base64.RawURLEncoding.EncodeToString(pk.PublicKey.Y.Bytes())
		keys = append(keys, map[string]interface{}{"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256", "x": x, "y": y})
	}
	return map[string]interface{}{"keys": keys}, nil
}

func (f *FileKeyManager) Sign(kid string, payload []byte) ([]byte, error) {
	f.mu.RLock()
	priv, ok := f.keys[kid]
	f.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key %s not found", kid)
	}
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
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

func (f *FileKeyManager) GenerateKey(name string, kty string, alg string) (*KeyMetadata, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405Z"))
	meta := &KeyMetadata{Kid: kid, Kty: "EC", Alg: "ES256", Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}
	f.mu.Lock()
	f.keys[kid] = priv
	f.meta[kid] = meta
	f.mu.Unlock()
	if err := f.saveKeyToDisk(kid, priv, meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func (f *FileKeyManager) RotateKey(name string) (*KeyMetadata, error) {
	return f.GenerateKey(name, "EC", "ES256")
}

func (f *FileKeyManager) ListKeys() ([]*KeyMetadata, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []*KeyMetadata{}
	for _, md := range f.meta {
		out = append(out, md)
	}
	return out, nil
}

func (f *FileKeyManager) RevokeKey(kid string) error {
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

func (f *FileKeyManager) SignKeyAnnouncement(newJWK map[string]interface{}, oldKid string, iss string, exp time.Duration) (string, error) {
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
	sig, err := f.Sign(oldKid, []byte(signingInput))
	if err != nil {
		return "", err
	}
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigEnc, nil
}

func (f *FileKeyManager) ImportKey(name string, pemEncoded []byte, passphrase string) (*KeyMetadata, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	kid := fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405Z"))
	meta := &KeyMetadata{Kid: kid, Kty: "EC", Alg: "ES256", Status: KeyStatusStandby, CreatedAt: time.Now().UTC()}
	f.mu.Lock()
	f.keys[kid] = priv
	f.meta[kid] = meta
	f.mu.Unlock()
	if err := f.saveKeyToDisk(kid, priv, meta); err != nil {
		return nil, err
	}
	return meta, nil
}
