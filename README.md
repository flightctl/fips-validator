# FIPS Validator

Tool for validating that a binary, an RPM package, or an OCI container image has been built so it can run on a FIPS-verified system.

## Description

`fips-validator` validates cryptographic binaries using either Go's native certified FIPS module or OpenSSL's FIPS provider. Go 1.27+ binaries can use the native module; older Go binaries and non-Go binaries continue to require OpenSSL-backed crypto. For container images, the tool also checks that OpenSSL's `libcrypto.so` is present in the image.

To build a Go binary with FIPS-verified crypto:

- With Go 1.27+, set `GOFIPS140=v1.0.0` to select the certified native Go FIPS module. The validator requires the binary to enable FIPS mode by default or on FIPS-enabled hosts and to contain the module integrity information.
- With Go 1.23–1.26, use a toolchain patched to use OpenSSL for crypto operations, such as the toolchain provided by the `registry.access.redhat.com/ubi9/go-toolset:latest` image. Set `CGO_ENABLED=1` and `GOEXPERIMENT=strictfipsruntime` when building.
- Avoid the `no_openssl` build tag when using OpenSSL-backed Go crypto.

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
