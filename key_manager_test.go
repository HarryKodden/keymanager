package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

func TestMemoryKeyManager_GenerateSign(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryKeyManager()
	meta, err := m.GenerateKey(ctx, "test", "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if meta == nil || meta.Kid == "" {
		t.Fatalf("invalid metadata returned")
	}

	jwks, err := m.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	keys, _ := jwks["keys"].([]interface{})
	if len(keys) == 0 {
		t.Fatalf("expected jwks keys")
	}

	if err := m.ActivateKey(ctx, meta.Kid); err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}

	sig, err := m.Sign(ctx, meta.Kid, []byte("input"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}

	ann, err := m.SignKeyAnnouncement(ctx, map[string]interface{}{"kid": "new"}, meta.Kid, "iss", 60)
	if err != nil {
		t.Fatalf("SignKeyAnnouncement failed: %v", err)
	}
	if parts := strings.Split(ann, "."); len(parts) != 3 {
		t.Fatalf("announcement not compact JWT")
	}
}

func TestFileKeyManager_PersistLoad(t *testing.T) {
	dir := t.TempDir()
	pass := "s3cr3t-pass"
	ctx := context.Background()
	f := NewFileKeyManager(dir, pass)

	meta, err := f.GenerateKey(ctx, "testfile", "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if meta == nil || meta.Kid == "" {
		t.Fatalf("invalid metadata")
	}

	// Activate the key so it can be used for signing and is persisted active
	if err := f.ActivateKey(ctx, meta.Kid); err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}

	// Create a fresh manager and load from disk
	f2 := NewFileKeyManager(dir, pass)
	if err := f2.LoadKeys(ctx); err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	list, err := f2.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(list) == 0 {
		t.Fatalf("expected at least one key after load")
	}

	sig, err := f2.Sign(ctx, meta.Kid, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}

	ann, err := f2.SignKeyAnnouncement(ctx, map[string]interface{}{"kid": "new"}, meta.Kid, "iss", 60)
	if err != nil {
		t.Fatalf("SignKeyAnnouncement failed: %v", err)
	}
	if parts := strings.Split(ann, "."); len(parts) != 3 {
		t.Fatalf("announcement not compact JWT")
	}

	// Test ImportKey: create a new EC key PEM and import
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec private: %v", err)
	}
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(pemBlock)
	im, err := f2.ImportKey(ctx, "imported", pemBytes, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}
	if im == nil || im.Kid == "" {
		t.Fatalf("invalid import metadata")
	}
}

func TestMemoryKeyManager_RSA(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryKeyManager()
	meta, err := m.GenerateKey(ctx, "testrsa", "RSA", "RS256")
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}
	if meta == nil || meta.Kid == "" {
		t.Fatalf("invalid metadata returned")
	}
	jwks, err := m.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	keys, _ := jwks["keys"].([]interface{})
	var found map[string]interface{}
	for _, ki := range keys {
		if k, ok := ki.(map[string]interface{}); ok {
			if k["kid"] == meta.Kid {
				found = k
				break
			}
		}
	}
	if found == nil {
		t.Fatalf("expected rsa jwk for kid %s", meta.Kid)
	}
	if found["kty"] != "RSA" {
		t.Fatalf("expected RSA jwk, got %v", found["kty"])
	}
	if err := m.ActivateKey(ctx, meta.Kid); err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}

	sig, err := m.Sign(ctx, meta.Kid, []byte("payload-rsa"))
	if err != nil {
		t.Fatalf("Sign RSA failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty rsa signature")
	}
	// verify signature using jwk n/e
	nb, _ := base64.RawURLEncoding.DecodeString(found["n"].(string))
	eb, _ := base64.RawURLEncoding.DecodeString(found["e"].(string))
	n := new(big.Int).SetBytes(nb)
	e := int(new(big.Int).SetBytes(eb).Int64())
	pub := &rsa.PublicKey{N: n, E: e}
	h := sha256.Sum256([]byte("payload-rsa"))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("rsa signature verify failed: %v", err)
	}
}

func TestFileKeyManager_RSA(t *testing.T) {
	dir := t.TempDir()
	pass := "s3cr3t-pass"
	ctx := context.Background()
	f := NewFileKeyManager(dir, pass)
	meta, err := f.GenerateKey(ctx, "testrsa", "RSA", "RS256")
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}
	if err := f.ActivateKey(ctx, meta.Kid); err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}

	f2 := NewFileKeyManager(dir, pass)
	if err := f2.LoadKeys(ctx); err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	jwks, err := f2.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	keys, _ := jwks["keys"].([]interface{})
	var found map[string]interface{}
	for _, ki := range keys {
		if k, ok := ki.(map[string]interface{}); ok {
			if k["kid"] == meta.Kid {
				found = k
				break
			}
		}
	}
	if found == nil {
		t.Fatalf("expected rsa jwk for kid %s", meta.Kid)
	}
	sig, err := f2.Sign(ctx, meta.Kid, []byte("payload-file-rsa"))
	if err != nil {
		t.Fatalf("Sign RSA failed: %v", err)
	}
	nb, _ := base64.RawURLEncoding.DecodeString(found["n"].(string))
	eb, _ := base64.RawURLEncoding.DecodeString(found["e"].(string))
	n := new(big.Int).SetBytes(nb)
	e := int(new(big.Int).SetBytes(eb).Int64())
	pub := &rsa.PublicKey{N: n, E: e}
	h := sha256.Sum256([]byte("payload-file-rsa"))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("rsa signature verify failed: %v", err)
	}
}

func TestActivateDeactivate_Memory(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryKeyManager()
	md, err := m.GenerateKey(ctx, "acttest", "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	// signing without activation should fail
	if _, err := m.Sign(ctx, md.Kid, []byte("x")); err == nil {
		t.Fatalf("expected error signing with standby key")
	} else if err != ErrKeyNotActive {
		t.Fatalf("expected ErrKeyNotActive, got %v", err)
	}
	if err := m.ActivateKey(ctx, md.Kid); err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}
	if _, err := m.Sign(ctx, md.Kid, []byte("x")); err != nil {
		t.Fatalf("Sign after activate failed: %v", err)
	}
	if err := m.DeactivateKey(ctx, md.Kid); err != nil {
		t.Fatalf("DeactivateKey failed: %v", err)
	}
	if _, err := m.Sign(ctx, md.Kid, []byte("x")); err == nil || err != ErrKeyNotActive {
		t.Fatalf("expected ErrKeyNotActive after deactivate, got %v", err)
	}
}

func TestGenerateAndActivate_File(t *testing.T) {
	dir := t.TempDir()
	pass := "s3cr3t"
	ctx := context.Background()
	f := NewFileKeyManager(dir, pass)
	md, err := f.GenerateAndActivate(ctx, "gandatest", "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateAndActivate failed: %v", err)
	}
	if _, err := f.Sign(ctx, md.Kid, []byte("payload")); err != nil {
		t.Fatalf("Sign after GenerateAndActivate failed: %v", err)
	}
	// reload from disk and ensure key remains active
	f2 := NewFileKeyManager(dir, pass)
	if err := f2.LoadKeys(ctx); err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	if _, err := f2.Sign(ctx, md.Kid, []byte("payload")); err != nil {
		t.Fatalf("Sign after reload failed: %v", err)
	}
}

func TestFileKeyManager_PKCS8(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pass := "s3cr3t-pkcs8"
	f := NewFileKeyManager(dir, pass)

	// create RSA key and encode as PKCS#8 PEM
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8: %v", err)
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(pemBlock)

	im, err := f.ImportKey(ctx, "pkcs8import", pemBytes, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS8 failed: %v", err)
	}
	if im == nil || im.Kid == "" {
		t.Fatalf("invalid import metadata")
	}

	if err := f.ActivateKey(ctx, im.Kid); err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}

	f2 := NewFileKeyManager(dir, pass)
	if err := f2.LoadKeys(ctx); err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	if _, err := f2.Sign(ctx, im.Kid, []byte("payload-pkcs8")); err != nil {
		t.Fatalf("Sign failed after load: %v", err)
	}
}
