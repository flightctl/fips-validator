package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanNonELFFiles(t *testing.T) {
	testCases := []struct {
		name  string
		data  string
		mode  os.FileMode
		valid bool
	}{
		{"When a short script is executable it should be skipped", "#!/bin/sh\n", 0700, true},
		{"When a script is executable it should be skipped", "#!/usr/bin/python3\nprint('ok')\n", 0700, true},
		{"When data is not executable it should be skipped", "plain data", 0600, true},
		{"When an executable is empty it should fail closed", "", 0700, false},
		{"When an executable is not recognized it should fail closed", "unrecognized executable", 0700, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "artifact"), []byte(testCase.data), testCase.mode); err != nil {
				t.Fatal(err)
			}
			if valid := ScanDirTree(context.Background(), root, func(string, ...interface{}) {}); valid != testCase.valid {
				t.Fatalf("valid=%v, want %v", valid, testCase.valid)
			}
		})
	}
}
