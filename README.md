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

Example (create file-backed manager):

```go
import "github.com/harrykodden/keymanager"

km := keymanager.NewFileKeyManager("./keys", "")
_ = km.LoadKeys()
md, err := km.GenerateKey("resolver", "EC", "ES256")
_ = md
```

## Running tests

Run tests from repository root (or inside `keymanager`):

```bash
go test ./keymanager -v
```

## CI

This repository uses GitHub Actions to run `gofmt`, `go vet`, and `go test`. The badge above points to the workflow at `.github/workflows/ci.yml` in the main repository. If you add or change workflows, update that path accordingly.

## Contributing

- Run `gofmt -w .` before committing.
- Keep `go.mod` and `go.sum` checked in for reproducible builds.

## License

This project is licensed under the Apache License, Version 2.0. See the `LICENSE` file at the project root for the full text.

Additionally a copy of the notice is included in this package under `keymanager/LICENSE`.
