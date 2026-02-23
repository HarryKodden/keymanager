package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestMemoryKeyManager_GenerateSign(t *testing.T) {
	m := NewMemoryKeyManager()
	meta, err := m.GenerateKey("test", "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if meta == nil || meta.Kid == "" {
		t.Fatalf("invalid metadata returned")
	}

	jwks, err := m.GetJWKS()
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	keys, _ := jwks["keys"].([]interface{})
	if len(keys) == 0 {
		t.Fatalf("expected jwks keys")
	}

	sig, err := m.Sign(meta.Kid, []byte("input"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}

	ann, err := m.SignKeyAnnouncement(map[string]interface{}{"kid": "new"}, meta.Kid, "iss", 60)
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
	f := NewFileKeyManager(dir, pass)

	meta, err := f.GenerateKey("testfile", "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if meta == nil || meta.Kid == "" {
		t.Fatalf("invalid metadata")
	}

	// Create a fresh manager and load from disk
	f2 := NewFileKeyManager(dir, pass)
	if err := f2.LoadKeys(); err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	list, err := f2.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(list) == 0 {
		t.Fatalf("expected at least one key after load")
	}

	sig, err := f2.Sign(meta.Kid, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}

	ann, err := f2.SignKeyAnnouncement(map[string]interface{}{"kid": "new"}, meta.Kid, "iss", 60)
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
	im, err := f2.ImportKey("imported", pemBytes, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}
	if im == nil || im.Kid == "" {
		t.Fatalf("invalid import metadata")
	}
}
