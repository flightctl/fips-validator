# FIPS Validator

Tool for validating that a binary, an RPM package, or an OCI container image has been built so it can run on a FIPS-verified system.

## Description

`fips-validator` statically checks binaries that use cryptographic algorithms.
Legacy Go binaries require the OpenSSL backend. Native hostfips binaries require
an explicitly supported certified Go module snapshot. For container images, the
tool still checks that OpenSSL's `libcrypto.so` is present in the image; native
binary support does not remove that existing image requirement.

Go 1.27 hostfips binaries are also supported when their build metadata selects
the certified native snapshot `GOFIPS140=v1.0.0-c2097c7c` and their ELF symbols
contain `go:fipsinfo`. CGO, dynamic linkage, and `strictfipsruntime` remain
required. Unknown versions and snapshots are rejected. This static validation
does not prove runtime activation: consumers must verify `crypto/fips140.Enabled()`
and `crypto/fips140.Version()` inside each shipped executable, and test that
strict runtime protection rejects disabled FIPS on an actual FIPS-enabled host.

For the legacy OpenSSL backend (Go 1.23 through 1.26):

- use a Golang toolchain >=1.23 that has been patched to use OpenSSL for crypto operations, e.g. using the toolchain provided by the `registry.access.redhat.com/ubi9/go-toolset:latest` image
- provide the `CGO_ENABLED=1` and `GOEXPERIMENT=strictfipsruntime` environment variables when building
- avoid using the `no_openssl` build tag

## Installation

This is the recommended method if you have the Go toolchain version >=1.23 installed. It will download, compile, and install the tool in your Go binary path:

```bash
go install github.com/flightctl/fips-validator@latest
```

## Building from source

Prerequisites:

- Go 1.23+
- Git

Steps:

```bash
git clone https://github.com/flightctl/fips-validator.git
cd fips-validator
go build
```

## Usage

To validate a binary, run:

```bash
fips-validator binary /path/to/binary
```

To validate an RPM package, you need to have the `rpm2cpio` and `cpio` tools installed on the system. Then run:

```bash
fips-validator rpm /path/to/package.rpm
```

To validate an OCI container image, you need to have `podman` installed on the system. You can then run the FIPS validator rootless in a `podman unshare` context:

```bash
podman unshare -- fips-validator image registry.example.com/repo/image:tag
```
