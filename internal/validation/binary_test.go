package validation

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/flightctl/fips-validator/pkg/elfinfo"
)

func TestUnreadableBinaryFailsClosed(t *testing.T) {
	if ValidateBinary(context.Background(), "/", filepath.Join(t.TempDir(), "missing"), func(string, ...interface{}) {}) {
		t.Fatal("unreadable binary was accepted")
	}
}

func TestBackendValidation(t *testing.T) {
	testCases := []struct {
		name     string
		version  string
		snapshot string
		symbol   string
		valid    bool
	}{
		{"When legacy OpenSSL is present it should pass", "1.26.7", "", "vendor/github.com/golang-fips/openssl/v2.dlopen", true},
		{"When legacy OpenSSL is absent it should fail", "1.26.7", "", "go:fipsinfo", false},
		{"When native certified snapshot is present it should pass", "1.27.3", "v1.0.0-c2097c7c", "go:fipsinfo", true},
		{"When native integrity symbol is absent it should fail", "1.27.3", "v1.0.0-c2097c7c", "other", false},
		{"When native snapshot is missing it should fail", "1.27.3", "", "go:fipsinfo", false},
		{"When native snapshot is off it should fail", "1.27.3", "off", "go:fipsinfo", false},
		{"When native snapshot is latest it should fail", "1.27.3", "latest", "go:fipsinfo", false},
		{"When native snapshot is an unresolved alias it should fail", "1.27.3", "certified", "go:fipsinfo", false},
		{"When native snapshot is unknown it should fail", "1.27.3", "v1.26.0", "go:fipsinfo", false},
		{"When older toolset uses native crypto it should fail", "1.26.7", "v1.0.0-c2097c7c", "go:fipsinfo", false},
		{"When future toolset is unknown it should fail", "1.28.0", "v1.0.0-c2097c7c", "go:fipsinfo", false},
		{"When toolset predates support it should fail", "1.22.0", "", "vendor/github.com/golang-fips/openssl/v2.dlopen", false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			info := &elfinfo.ElfInfo{Sections: []string{"", ".text"}, Symbols: []elf.Symbol{{Name: testCase.symbol, Section: 1}}}
			build := &buildinfo.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOFIPS140", Value: testCase.snapshot}}}
			version := semver.MustParse(testCase.version)
			errs := append(validateGoSymbols(info, version), validateGoBackend(build, version)...)
			if (len(errs) == 0) != testCase.valid {
				t.Fatalf("valid=%v, errors=%v", testCase.valid, errs)
			}
		})
	}
}

func TestStrictRuntimeExperiment(t *testing.T) {
	for _, experiment := range []string{"", "nostrictfipsruntime", "strictfipsruntime,nostrictfipsruntime", "strictfipsruntime,none", "notstrictfipsruntime"} {
		t.Run("When experiment is "+experiment+" it should fail", func(t *testing.T) {
			info := &buildinfo.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOEXPERIMENT", Value: experiment}}}
			if len(validateGoTagsAndExperiment(info)) == 0 {
				t.Fatal("accepted missing or disabled strict runtime")
			}
		})
	}
	if len(validateGoTagsAndExperiment(&buildinfo.BuildInfo{})) == 0 {
		t.Fatal("accepted absent experiment metadata")
	}
	info := &buildinfo.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "other,strictfipsruntime"}}}
	if errs := validateGoTagsAndExperiment(info); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestLinkageAndTags(t *testing.T) {
	if len(validateCgoEnabled(&buildinfo.BuildInfo{})) == 0 {
		t.Fatal("accepted missing CGO metadata")
	}
	if len(validateNotStaticallyLinked(&elfinfo.ElfInfo{IsStatic: true})) == 0 {
		t.Fatal("accepted a static binary")
	}
	if len(validateCgoInit(&elfinfo.ElfInfo{})) == 0 {
		t.Fatal("accepted missing CGO initialization")
	}
	info := &buildinfo.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "GOEXPERIMENT", Value: "strictfipsruntime"},
		{Key: "-tags", Value: "no_openssl"},
	}}
	if len(validateGoTagsAndExperiment(info)) == 0 {
		t.Fatal("accepted forbidden crypto build tag")
	}
	elfInfo := &elfinfo.ElfInfo{Sections: []string{"", ".bss"}, Symbols: []elf.Symbol{{Name: "go:fipsinfo", Section: 1}}}
	if len(validateGoSymbols(elfInfo, semver.MustParse("1.27.3"))) == 0 {
		t.Fatal("accepted uninitialized FIPS integrity symbol")
	}
}
