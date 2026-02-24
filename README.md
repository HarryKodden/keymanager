
# Key Manager

![Go](https://img.shields.io/badge/go-1.25-blue.svg)
![CI](https://github.com/harrykodden/keymanager/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

Lightweight Go utilities for key management used by the OpenID Federation resolver and related components.

## Purpose

- Provide `Memory`, `File`, and `Vault (transit)` key storage implementations.
- Offer key lifecycle operations: `GenerateKey`, `RotateKey`, `ActivateKey`, `DeactivateKey`, `RevokeKey`, and `ListKeys`.
- Signing support for `ES256` (ECDSA P-256) and `RS256` (RSA) via `Sign`.
- JWKS emission and key import/persistence helpers (the File manager persists encrypted PKCS#8 blobs).

## Highlights

- All public APIs accept `context.Context` for cancellation and tracing.
- Typed errors: `ErrKeyNotFound`, `ErrKeyNotActive`, `ErrUnsupportedOperation`.
- `GenerateKey` defaults to `standby`; use `ActivateKey` or `GenerateAndActivate` to make a key active.
- RSA support (generate, sign, JWKS) and configurable RSA size via `KEYMANAGER_RSA_BITS` (default: 2048).
- File-backed key storage encrypts PKCS#8 blobs with AES-GCM derived from the provided passphrase.

## Quick start

Prefer using the factory which selects a backend based on environment variables:

```go
import (
	"context"
	"github.com/harrykodden/keymanager"
)

ctx := context.Background()
km, err := keymanager.NewDefaultKeyManager()
if err != nil {
	// handle error
}
_ = km.LoadKeys(ctx)

md, err := km.GenerateAndActivate(ctx, "resolver", "EC", "ES256")
if err != nil {
	// handle
}

sig, err := km.Sign(ctx, md.Kid, []byte("payload-to-sign"))
_ = sig

jwks, err := km.GetJWKS(ctx)
_ = jwks
```

Construct backends directly when required:

```go
// File-backed (persisted, encrypted PKCS#8 blobs)
f := keymanager.NewFileKeyManager("./keys", "my-passphrase")
_ = f.LoadKeys(ctx)

// In-memory (ephemeral)
m := keymanager.NewMemoryKeyManager()

// Vault (transit) - requires a configured Vault client
// vc := vault.NewClient(cfg)
// v := keymanager.NewVaultKeyManager(vc, "transit")
```

## Importing keys

`FileKeyManager.ImportKey(ctx, name, pemBytes, passphrase)`

accepts PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`), as well as PKCS#1 RSA PEM (`-----BEGIN RSA PRIVATE KEY-----`) and SEC1 EC PEM (`-----BEGIN EC PRIVATE KEY-----`) formats.

Example (PKCS#8 RSA import):

```go
rsaKeyPem := /* PEM bytes containing a PKCS#8 PRIVATE KEY */
meta, err := f.ImportKey(ctx, "imported", rsaKeyPem, "")
_ = meta
```

## Configuration & environment

- `KEYMANAGER_RSA_BITS` — default RSA key size for generated RSA keys (e.g., `export KEYMANAGER_RSA_BITS=4096`).
- `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_MOUNT` — when set, `NewDefaultKeyManager()` will prefer Vault Transit.
- `KEYS_DIR`, `PASSPHRASE` — used to enable `FileKeyManager` when Vault is not configured.

## Examples

Generate, activate, and sign with `FileKeyManager`:

```go
ctx := context.Background()
f := keymanager.NewFileKeyManager("./keys", "s3cr3t-pass")
_ = f.LoadKeys(ctx)
md, _ := f.GenerateAndActivate(ctx, "app", "RSA", "RS256")
sig, _ := f.Sign(ctx, md.Kid, []byte("hello"))
fmt.Printf("sig len=%d\n", len(sig))
```

Export JWKS (publishable JSON):

```go
jwks, _ := f.GetJWKS(ctx)
// encode to JSON when serving over HTTP
```

## Testing

Run unit tests:

```bash
gofmt -w .
go test ./... -v
```

## Contributing

- Run `gofmt -w .` before committing.
- Keep `go.mod` and `go.sum` checked in for reproducible builds.

## License

This project is licensed under the Apache License, Version 2.0. See the `LICENSE` file at the project root for the full text.
