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
import "github.com/harrykodden/keymanager"

km, err := keymanager.NewDefaultKeyManager()
if err != nil {
	// handle error
}
_ = km.LoadKeys()
md, err := km.GenerateKey("resolver", "EC", "ES256")
_ = md
```

If you need to explicitly construct a backend, you can still use the concrete
constructors:

```go
// file-backed
km := keymanager.NewFileKeyManager("./keys", "my-passphrase")

// in-memory (ephemeral)
km := keymanager.NewMemoryKeyManager()

// vault (requires vault client)
// vc := vault.NewClient(cfg)
// km := keymanager.NewVaultKeyManager(vc, "transit")
```

## Running tests

Run tests from repository root (or inside `keymanager`):

```bash
go test ./keymanager -v
```

## CI

This repository uses GitHub Actions to run `gofmt`, `go vet`, and `go test`. The badge above points to the workflow at `.github/workflows/ci.yml` in the main repository. If you add or change workflows, update that path accordingly.

## Backends & configuration

`NewDefaultKeyManager()` selects the backend by inspecting environment variables in this order:

- Vault: If both `VAULT_ADDR` and `VAULT_TOKEN` are set, the factory will create a `VaultKeyManager` and use the Transit engine (mount name from `VAULT_TRANSIT_MOUNT`, default `transit`).
- File: If `KEYS_DIR` and `PASSPHRASE` are set (and Vault is not configured), the factory will create a `FileKeyManager` storing encrypted key blobs under `KEYS_DIR`.
- Memory: Otherwise the factory returns a `MemoryKeyManager` (ephemeral keys only).

Set environment variables before starting the resolver or any application that calls `NewDefaultKeyManager()` to control the backend. Examples:

Vault (Transit):

```bash
export VAULT_ADDR=https://vault.example:8200
export VAULT_TOKEN=s.Xxx...
export VAULT_TRANSIT_MOUNT=transit   # optional
```

File-backed:

```bash
export KEYS_DIR=/var/lib/myapp/keys
export PASSPHRASE="correct horse battery staple"
```

Memory (default):

```bash
unset VAULT_ADDR VAULT_TOKEN KEYS_DIR PASSPHRASE
```

## Contributing

- Run `gofmt -w .` before committing.
- Keep `go.mod` and `go.sum` checked in for reproducible builds.

## License

This project is licensed under the Apache License, Version 2.0. See the `LICENSE` file at the project root for the full text.

Additionally a copy of the notice is included in this package under `keymanager/LICENSE`.
