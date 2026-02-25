package keymanager

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// This integration test exercises the VaultKeyManager against a real Vault
// instance. It is skipped by default; set the following environment vars to run:
//
//	RUN_VAULT_INTEGRATION_TESTS=1
//	VAULT_ADDR=https://... (your Vault address)
//	VAULT_TOKEN=...(a token with transit permissions)
//
// The test will attempt to create a transit key, activate it (rotate), sign
// a payload, and then attempt cleanup. It provides clear errors when the
// transit mount or permissions are missing.
func TestVaultIntegration(t *testing.T) {
	// Load .env if present to make it easy to run locally with stored vars
	loadDotEnv()

	if os.Getenv("RUN_VAULT_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_VAULT_INTEGRATION_TESTS=1 and VAULT_ADDR/VAULT_TOKEN to run")
	}

	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Fatal("VAULT_ADDR and VAULT_TOKEN must be set to run this test")
	}

	cfg := vault.DefaultConfig()
	cfg.Address = addr
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	client.SetToken(token)

	mount := os.Getenv("VAULT_TRANSIT_MOUNT")
	if mount == "" {
		mount = "transit"
	}

	vkm := NewVaultKeyManager(client, mount)

	ctx := context.Background()
	name := fmt.Sprintf("km-integ-%d", time.Now().Unix())

	// Attempt to create the key in Vault transit
	md, err := vkm.GenerateKey(ctx, name, "EC", "ES256")
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Try to activate (rotate) so there's an active version
	if err := vkm.ActivateKey(ctx, md.Kid); err != nil {
		t.Fatalf("ActivateKey error: %v", err)
	}

	// Sign a payload
	payload := []byte("integration-test-payload")
	sig, err := vkm.Sign(ctx, md.Kid, payload)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("received empty signature")
	}

	// Best-effort cleanup: attempt to revoke the key (may require extra perms)
	if err := vkm.RevokeKey(ctx, md.Kid); err != nil {
		t.Logf("RevokeKey failed (cleanup): %v", err)
	}
}

// loadDotEnv reads a .env file in the repository root (if present) and sets
// environment variables for any keys that are not already set. It tolerates
// simple KEY=VALUE lines and ignores comments/empty lines.
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	if n == 0 {
		return
	}
	content := string(buf[:n])
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// remove optional surrounding quotes
		if len(val) >= 2 && ((val[0] == '\'' && val[len(val)-1] == '\'') || (val[0] == '"' && val[len(val)-1] == '"')) {
			val = val[1 : len(val)-1]
		}
		if key == "" {
			continue
		}
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
