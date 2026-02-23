package keymanager

import (
	"log"
	"os"

	vault "github.com/hashicorp/vault/api"
)

// NewDefaultKeyManager returns an AdvancedKeyManager chosen by environment variables.
// Priority (new):
// 1) If VAULT_ADDR and VAULT_TOKEN are set -> VaultKeyManager
// 2) Else if KEYS_DIR and PASSPHRASE are set -> FileKeyManager
// 3) Otherwise -> MemoryKeyManager (ephemeral)
func NewDefaultKeyManager() (AdvancedKeyManager, error) {
	// 1) Vault
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultAddr != "" && vaultToken != "" {
		cfg := vault.DefaultConfig()
		cfg.Address = vaultAddr
		vc, err := vault.NewClient(cfg)
		if err != nil {
			return nil, err
		}
		vc.SetToken(vaultToken)
		transit := os.Getenv("VAULT_TRANSIT_MOUNT")
		if transit == "" {
			transit = "transit"
		}
		log.Printf("[KEYMANAGER] backend=vault transit=%s", transit)
		return NewVaultKeyManager(vc, transit), nil
	}

	// 2) File-backed when KEYS_DIR and PASSPHRASE provided
	keysDir := os.Getenv("KEYS_DIR")
	pass := os.Getenv("PASSPHRASE")
	if keysDir != "" && pass != "" {
		log.Printf("[KEYMANAGER] backend=file dir=%s", keysDir)
		return NewFileKeyManager(keysDir, pass), nil
	}

	// 3) Default: memory (ephemeral)
	log.Printf("[KEYMANAGER] backend=memory (ephemeral)")
	return NewMemoryKeyManager(), nil
}
