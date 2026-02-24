# Key Manager

![Go](https://img.shields.io/badge/go-1.25-blue.svg)
![CI](https://github.com/harrykodden/keymanager/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

Lightweight key management utilities used by the OpenID Federation resolver and related components.

## Purpose

- Provide in-memory and file-backed key storage implementations.
- Offer key lifecycle operations (generate, rotate, list, revoke) and signing helpers.
- Expose JWKS for publishing public keys.

## Quick Start

From the repository root use the module normally; the package provides a Go API.

The package exposes a helper `NewDefaultKeyManager()` which selects an appropriate
backend based on environment variables (see "Backends & configuration" below).

Example (preferred: let the keymanager choose):

```go
````markdown
# Key Manager

![Go](https://img.shields.io/badge/go-1.25-blue.svg)
![CI](https://github.com/harrykodden/keymanager/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

Lightweight key management utilities used by the OpenID Federation resolver and related components.

## Purpose

- Provide `Memory`, `File`, and `Vault (transit)` key storage implementations.
- Offer key lifecycle operations: `GenerateKey`, `RotateKey`, `ActivateKey`, `DeactivateKey`, `RevokeKey` and `ListKeys`.
- Signing support (`Sign`) for `ES256` (ECDSA P-256) and `RS256` (RSA).
- JWKS emission and import/persistence helpers (File manager persists encrypted PKCS#8 blobs).

## Highlights / New features

- All public APIs accept `context.Context` for cancellation and tracing.
- Typed errors exported: `ErrKeyNotFound`, `ErrKeyNotActive`, `ErrUnsupportedOperation`.
- `GenerateKey` now defaults to `standby` status; use `ActivateKey` or `GenerateAndActivate` to make active.
- RSA support added (generate, sign, JWKS). RSA private keys are persisted as PKCS#8.
- Centralized helpers for JWKS and signatures (`jwkFromPublicKey`, `SignPayload`, `ECDSADERToRaw`).
- File-backed key storage encrypts key blobs with AES-GCM derived from the provided passphrase.
- Configurable RSA bits: set `KEYMANAGER_RSA_BITS` env var (default: 2048).

## Quick Start

Preferred: use the factory which selects a backend based on env vars:

```go
import (
	"context"
	"github.com/harrykodden/keymanager"
)

ctx := context.Background()
km, err := keymanager.NewDefaultKeyManager()
if err != nil {
	// handle
}
_ = km.LoadKeys(ctx)

// generate a key (standby) and then activate it
md, err := km.GenerateAndActivate(ctx, "resolver", "EC", "ES256")
_ = md

// sign a payload
sig, err := km.Sign(ctx, md.Kid, []byte("payload-to-sign"))
_ = sig

// get JWKS to publish
jwks, err := km.GetJWKS(ctx)
_ = jwks
```

Constructing backends directly:

```go
// file-backed (persisted, encrypted PKCS#8 blobs)
f := keymanager.NewFileKeyManager("./keys", "my-passphrase")
_ = f.LoadKeys(ctx)

// in-memory (ephemeral)
m := keymanager.NewMemoryKeyManager()

// vault (transit) - requires a configured Vault client
// vc := vault.NewClient(cfg)
// v := keymanager.NewVaultKeyManager(vc, "transit")
```

## Importing keys (PKCS#8 and legacy formats)

`FileKeyManager.ImportKey(ctx, name, pemBytes, passphrase)` accepts PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) as well as RSA (`-----BEGIN RSA PRIVATE KEY-----`) and EC (`-----BEGIN EC PRIVATE KEY-----`) PEM formats.

Example (PKCS#8 RSA import):

```go
rsaKeyPem := /* PEM bytes containing a PKCS#8 PRIVATE KEY */
meta, err := f.ImportKey(ctx, "imported", rsaKeyPem, "")
_ = meta
```

## Configuration & Environment

- `KEYMANAGER_RSA_BITS` — optional. Default RSA key size used for programmatically generated RSA keys. Example: `export KEYMANAGER_RSA_BITS=4096`.
- `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_MOUNT` — when set, `NewDefaultKeyManager()` will prefer Vault Transit.
- `KEYS_DIR`, `PASSPHRASE` — used to enable `FileKeyManager` when Vault is not configured.

## Examples

- Generate + activate and sign with `FileKeyManager`:

```go
ctx := context.Background()
f := keymanager.NewFileKeyManager("./keys", "s3cr3t-pass")
_ = f.LoadKeys(ctx)
md, _ := f.GenerateAndActivate(ctx, "app", "RSA", "RS256")
sig, _ := f.Sign(ctx, md.Kid, []byte("hello"))
fmt.Printf("sig len=%d\n", len(sig))
```

- Export JWKS (publishable JSON):

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

````
