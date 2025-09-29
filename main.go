package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"

	"github.com/flightctl/fips-validator/internal/executor"
	"github.com/flightctl/fips-validator/internal/scanner"
	"github.com/flightctl/fips-validator/internal/validation"
)

var (
	debugEnabled bool
	noColor      bool
	help         bool
)

var (
	info    = color.New(color.Bold).PrintfFunc()
	success = color.New(color.Bold, color.FgGreen).PrintfFunc()
	failure = color.New(color.Bold, color.FgRed).PrintfFunc()
)

func debug(format string, a ...interface{}) {
	if debugEnabled {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", a...)
	}
}

func usage(err error) {
	fd, rc := os.Stdout, 0
	if err != nil {
		fd, rc = os.Stderr, 2
		fmt.Fprintf(fd, "Error: %v\n\n", err)
	}

	fmt.Fprintf(fd, `%[1]s validates that an RPM package, OCI image, or binary is capable of running in FIPS mode.

Usage:
  %[1]s [flags] binary <path_to_executable>
  %[1]s [flags] rpm <path_to_rpm_file>
  podman unshare -- %[1]s [flags] image <oci_image_ref>

Flags:
  --debug      Enable debug output
  --no-color   Disable colored output
  --help       Show this help message
`, filepath.Base(os.Args[0]))

	os.Exit(rc)
}

func main() {
	flag.BoolVar(&debugEnabled, "debug", false, "Enable debug output")
	flag.BoolVar(&noColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&help, "help", false, "Show help")
	flag.Parse()

	if help {
		usage(nil)
	}

	color.NoColor = noColor

	args := flag.Args()
	if len(args) != 2 {
		usage(fmt.Errorf("incorrect number of arguments"))
	}
	mode := args[0]
	target := args[1]

	valid := true
	var err error
	switch mode {
	case "binary":
		valid, err = validateBinary(target)
	case "rpm":
		valid, err = validateRpmPackage(target)
	case "image":
		valid, err = validateOciImage(target)
	default:
		usage(fmt.Errorf("unknown mode %q", mode))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err.Error())
		os.Exit(1)
	}
	if !valid {
		failure("Validation failed\n")
		os.Exit(1)
	}
	success("Validation successful\n")
	os.Exit(0)
}

func validateBinary(binaryPath string) (bool, error) {
	path, err := filepath.Abs(binaryPath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path: %v", err)
	}
	info("Validating binary %q:\n", path)

	return validation.ValidateBinary(context.TODO(), "/", path, debug), nil
}

func validateRpmPackage(packagePath string) (bool, error) {
	path, err := filepath.Abs(packagePath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path: %v", err)
	}
	info("Validating RPM package %q:\n", path)

	tempDir, err := os.MkdirTemp("", "fips-validator-")
	if err != nil {
		return false, fmt.Errorf("failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	debug("Using temporary directory %s\n", tempDir)

	if err := unpackRPM(packagePath, tempDir); err != nil {
		return false, fmt.Errorf("failed to unpack RPM package: %v", err)
	}
	return scanner.ScanDirTree(context.TODO(), tempDir, debug), nil
}

func unpackRPM(packagePath, destDir string) error {
	fmt.Printf("• unpacking RPM... ")
	_, stderr, rc, err := executor.Execute(context.TODO(), destDir, "sh", "-c", fmt.Sprintf("rpm2cpio %s | cpio -idmv", packagePath))
	if err != nil {
		return errors.New(string(stderr))
	}
	if rc != 0 {
		return fmt.Errorf("failed to unpack RPM, exit code %d: %s", rc, string(stderr))
	}
	success("done\n")
	return nil
}

func validateOciImage(imageRef string) (bool, error) {
	info("Validating OCI image %q:\n", imageRef)

	tempDir, err := mountOciImage(imageRef)
	if err != nil {
		return false, err
	}
	defer unmountOciImage(imageRef)
	debug("Using temporary directory: %s", tempDir)

	allValid := true
	if !validation.ValidateOpenSSL(context.TODO(), tempDir) {
		allValid = false
	}
	if !scanner.ScanDirTree(context.TODO(), tempDir, debug) {
		allValid = false
	}
	return allValid, nil
}

func mountOciImage(imageRef string) (string, error) {
	fmt.Printf("• checking OCI image exists locally... ")
	_, _, rc, err := executor.Execute(context.TODO(), "", "podman", "image", "exists", imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to check whether image exists: %v", err)
	}
	if rc == 0 {
		success("found\n")
	} else {
		info("not found\n")

		fmt.Printf("• pulling image... ")
		_, stderr, rc, err := executor.Execute(context.TODO(), "", "podman", "pull", imageRef)
		if err != nil {
			return "", fmt.Errorf("failed to pull image: %s", err)
		}
		if rc != 0 {
			return "", fmt.Errorf("failed to pull image, exit code %d: %s", rc, string(stderr))
		}
		success("done\n")
	}

	fmt.Printf("• mounting OCI image... ")
	cmdArgs := []string{"image", "mount", imageRef}
	stdout, stderr, rc, err := executor.Execute(context.TODO(), "", "podman", cmdArgs...)
	if err != nil {
		return "", fmt.Errorf("failed to mount image: %s", string(stderr))
	}
	if rc != 0 {
		return "", fmt.Errorf("failed to mount image, exit code %d: %s", rc, string(stderr))
	}
	success("done\n")

	mountPath := string(stdout)
	mountPath = mountPath[:len(mountPath)-1] // Remove trailing newline
	return mountPath, nil
}

func unmountOciImage(imageRef string) error {
	fmt.Printf("• unmounting OCI image... ")
	_, stderr, rc, err := executor.Execute(context.TODO(), "", "podman", "image", "unmount", imageRef)
	if err != nil {
		return fmt.Errorf("failed to unmount image: %v", err)
	}
	if rc != 0 {
		return fmt.Errorf("failed to unmount image, exit code %d: %s", rc, string(stderr))
	}
	success("done\n")
	return nil
}
