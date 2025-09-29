package validation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/fatih/color"

	"github.com/flightctl/fips-validator/internal/executor"
)

var libPaths = []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib"}
var cryptoLibRegex = regexp.MustCompile(`^libcrypto.*\.so($|\..*)`)

func ValidateOpenSSL(ctx context.Context, rootPath string) bool {
	var errs []error
	success := color.New(color.Bold, color.FgGreen).PrintfFunc()
	failure := color.New(color.Bold, color.FgRed).PrintfFunc()
	red := color.New(color.Bold, color.FgRed).SprintfFunc()

	fmt.Printf("• validating libcrypto is present and FIPS-capable... ")

	cryptoLibs := findCryptoLibs(rootPath)
	if len(cryptoLibs) == 0 {
		errs = append(errs, fmt.Errorf("libcrypto not found (missing package openssl-libs?)"))
	} else {
		for _, lib := range cryptoLibs {
			stdout, stderr, rc, err := executor.Execute(ctx, "", "nm", "-D", filepath.Join(rootPath, lib))
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if rc != 0 {
				errs = append(errs, errors.New(string(stderr)))
				continue
			}

			hasFIPS := bytes.Contains(stdout, []byte("FIPS_mode")) ||
				bytes.Contains(stdout, []byte("fips_mode")) ||
				bytes.Contains(stdout, []byte("EVP_default_properties_is_fips_enabled"))
			if !hasFIPS {
				errs = append(errs, fmt.Errorf("%s is not FIPS-capable", lib))
			}
		}
	}

	if len(errs) > 0 {
		failure("failed\n")
		for _, e := range errs {
			fmt.Printf("  %s %v\n", red("✘"), e)
		}
		return false
	}
	success("success\n")
	return true
}

func findCryptoLibs(rootPath string) []string {
	var libs []string
	for _, libPath := range libPaths {
		dir := filepath.Join(rootPath, libPath)

		if dirInfo, err := os.Lstat(dir); err != nil || dirInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() && entry.Type().IsRegular() {
				if cryptoLibRegex.MatchString(entry.Name()) {
					libs = append(libs, filepath.Join(libPath, entry.Name()))
				}
			}
		}
	}
	return libs
}
