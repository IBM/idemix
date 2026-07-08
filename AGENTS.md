This file provides guidance to agents when working with code in this repository.

## What this project is

A Go implementation of an anonymous identity stack (Identity Mixer / Idemix) for blockchain systems, originally designed for use with Hyperledger Fabric. It provides zero-knowledge proof-based credentials: users can prove possession of a CA-signed credential and selectively disclose attributes (OU, Role, EnrollmentID, RevocationHandle) without revealing their identity.

## Commands

```bash
# CI entry point: checks + unit-tests + unit-tests-race
make all

# Format, vet, and license-header check
make checks             # runs check-deps, gofmt, go vet, addlicense -check
make fmt                # apply gofmt -l -s -w in place

# Tests
make unit-tests         # go test ./...
make unit-tests-race    # go test -race -cover with GORACE=history_size=7, 960s timeout

# Run a single package or test directly
go test ./bccsp/schemes/aries/...
go test ./bccsp/schemes/aries/ -run TestSignerSign

# Build idemixgen tool
make idemixgen          # go install ./tools/idemixgen → $GOPATH/bin
make binaries           # cross-compile to bin/amd64/ (linux) and bin/arm64/ (darwin)

# Protobuf regeneration
make installbuf         # installs buf@v1.70.0
make genprotos          # buf generate --template buf.gen.yaml

# Tidy modules
make tidy
```

## Architecture

### Two cryptographic schemes

The codebase implements two parallel cryptographic backends, both exposed through the same BCCSP interface:

1. **Legacy / dlog** (`bccsp/schemes/dlog/`) — The original Idemix implementation using discrete log proofs. It takes a `*math.Curve` and a `Translator` (handles curve-specific serialization). Instantiated via `idemix.New(keyStore, curve, translator, exportable)`.

2. **Aries** (`bccsp/schemes/aries/`) — A newer implementation using BBS+ signatures for credential issuance, intended to replace the dlog scheme. Instantiated via `idemix.NewAries(keyStore, curve, translator, exportable)`.

The **legacy guard** in CI enforces that new code must not add new imports of `schemes/dlog` or `schemes/weak-bb` outside of the known files listed in `.github/workflows/go.yml`. New code should use the Aries scheme.

### Package structure

```
bccsp/
  types/          # Interfaces: Issuer, User, CredRequest, Credential, SignatureScheme, etc.
  handlers/       # BCCSP operation wrappers: IssuerKeyGen, UserKeyGen, Signer, Verifier, etc.
  keystore/       # Key storage implementations
  schemes/
    aries/        # Aries/BBS+ implementation of all bccsp/types interfaces
    dlog/
      bridge/     # Adapts dlog/crypto to bccsp/types interfaces
      crypto/     # Core dlog Idemix math (signature, credential, nym, revocation)
    weak-bb/      # Weak Boneh-Boyen signatures (used internally for revocation)
  bccsp.go        # New() and NewAries() constructors; multiplexer wiring
  impl.go         # CSP base: type-keyed dispatch maps for KeyGen/Sign/Verify/etc.

bbs/              # BBS+ signature implementation (used by aries/Cred)

msp/              # Hyperledger Fabric MSP integration: credential lifecycle,
                  # attribute indices (OU=0, Role=1, EnrollmentID=2, RevocationHandle=3)

tools/idemixgen/  # CLI tool to generate issuer keys and signer configs for Fabric MSP
```

### BCCSP dispatch pattern

`CSP` (in `bccsp/impl.go`) is a generic dispatcher that holds `map[reflect.Type]Signer` (and similar maps for KeyGen/Verify/Import/Deriv). Operations are routed by the Go type of the key or opts argument. `bccsp.go` wires concrete scheme implementations into these maps via `AddWrapper`. The `userSecreKeySignerMultiplexer` and `issuerPublicKeyVerifierMultiplexer` types handle cases where a single key type handles multiple opt types.

### Curve and translator

`github.com/IBM/mathlib` provides the elliptic curve abstractions (`*math.Curve`, `*math.G1`, `*math.G2`, `*math.Zr`). The `Translator` interface (dlog scheme) handles curve-specific protobuf serialization for group elements. The `bccsp/schemes/dlog/crypto/translator/amcl/` package provides concrete translators for each supported curve family (FP256BN, BLS12-381, etc.).

### Credential attributes

The four fixed attributes are accessed by index: OU (0), Role (1), EnrollmentID (2), RevocationHandle (3). These indices are referenced throughout `msp/` and must match across signing and verification.

### Protobuf

`.proto` files live alongside their generated `.pb.go` files. Run `make genprotos` (requires `buf`) to regenerate. The main proto files are `bccsp/schemes/dlog/crypto/idemix.proto` and `bccsp/schemes/aries/cred.proto`.
