package scanner

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/flightctl/fips-validator/internal/validation"
)

func ScanDirTree(ctx context.Context, rootPath string, debugFunc func(string, ...interface{})) bool {
	allValid := true

	err := filepath.WalkDir(rootPath, func(path string, file fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if file.IsDir() {
			return nil
		}
		// Skip over all non-regular files. This is a very fast check
		// as it does not require calling stat(2).
		if !file.Type().IsRegular() {
			return nil
		}
		// Check if the file has any x bits set. This is a slower check
		// as it calls lstat(2) under the hood.
		fi, err := file.Info()
		if err != nil {
			return err
		}
		if fi.Mode().Perm()&0o111 == 0 {
			// Not an executable.
			return nil
		}

		innerPath := stripMountPath(rootPath, path)
		if !validation.ValidateBinary(ctx, rootPath, innerPath, debugFunc) {
			allValid = false
		}
		return nil
	})
	if err != nil {
		return false
	}

	return allValid
}

func stripMountPath(mountPath, path string) string {
	return strings.TrimPrefix(path, mountPath)
}
