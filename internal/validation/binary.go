package validation

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"

	"github.com/flightctl/fips-validator/pkg/elfinfo"
)

type versionConstrainedReqs struct {
	versions     *semver.Constraints
	requirements []string
}

var (
	requiredSymbolsForGoVersions = []versionConstrainedReqs{
		{
			versions: newSemverConstraint(">= 1.23, < 1.27"),
			requirements: []string{
				"vendor/github.com/golang-fips/openssl/v2.dlopen",
			},
		},
		{
			versions: newSemverConstraint(">= 1.27, < 1.28"),
			requirements: []string{
				"go:fipsinfo",
			},
		},
	}
)

func newSemverConstraint(str string) *semver.Constraints {
	c, err := semver.NewConstraint(str)
	if err != nil {
		panic(fmt.Errorf("semver: can't parse constraint %v: %w", str, err))
	}
	return c
}

func ValidateBinary(_ context.Context, rootPath string, path string, debugFunc func(string, ...interface{})) bool {
	var errs []error
	success := color.New(color.Bold, color.FgGreen).PrintfFunc()
	failure := color.New(color.Bold, color.FgRed).PrintfFunc()
	red := color.New(color.Bold, color.FgRed).SprintfFunc()

	fmt.Printf("• validating binary %s... ", path)
	if isScript(filepath.Join(rootPath, path)) {
		fmt.Printf("skipped (shell script)\n")
		return true
	}

	ei, err := elfinfo.ReadFile(filepath.Join(rootPath, path))
	if err != nil {
		failure("failed to read ELF info: %v\n", err)
		return false
	}
	if !ei.IsElf {
		fmt.Printf("skipped (not an ELF executable)\n")
		return true // Skip is considered success
	}
	if len(ei.Symbols) == 0 {
		if _, err := buildinfo.ReadFile(filepath.Join(rootPath, path)); err == nil {
			failure("cannot validate Go binary without ELF symbols\n")
			return false
		}
	}
	if !usesCrypto(ei, debugFunc) {
		fmt.Printf("skipped (no crypto)\n")
		return true // Skip is considered success
	}
	errs = append(errs, validateNotStaticallyLinked(ei)...)

	bi, err := buildinfo.ReadFile(filepath.Join(rootPath, path))
	if err != nil {
		debugFunc("skipping further validation (not a Go binary): %v", err)
	} else {
		ver := strings.TrimPrefix(bi.GoVersion, "go")
		if i := strings.IndexByte(ver, ' '); i != -1 {
			ver = ver[:i]
		}
		goVersion, err := semver.NewVersion(ver)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse Go version %q: %v", bi.GoVersion, err))
		} else {
			errs = append(errs, validateCgoEnabled(bi)...)
			errs = append(errs, validateCgoInit(ei)...)
			errs = append(errs, validateGoSymbols(ei, goVersion)...)
			errs = append(errs, validateGoTagsAndExperiment(bi)...)
			errs = append(errs, validateGoBackend(bi, goVersion)...)
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

func isScript(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	var magic [2]byte
	_, err = io.ReadFull(file, magic[:])
	return err == nil && string(magic[:]) == "#!"
}

func usesCrypto(info *elfinfo.ElfInfo, debugFunc func(string, ...interface{})) bool {
	for _, sym := range info.Symbols {
		if sym.Section >= elf.SHN_LORESERVE || int(sym.Section) >= len(info.Sections) {
			continue
		}
		section := info.Sections[sym.Section]
		if strings.Contains(sym.Name, "crypto") && !slices.Contains([]string{".bss"}, section) {
			debugFunc("found crypto symbol %q in section %q", sym.Name, section)
			return true
		}
	}
	return false
}

func validateNotStaticallyLinked(info *elfinfo.ElfInfo) []error {
	if info.IsStatic {
		return []error{fmt.Errorf("statically linked")}
	}
	return []error{}
}

func validateCgoEnabled(bi *buildinfo.BuildInfo) []error {
	for _, bs := range bi.Settings {
		if bs.Key == "CGO_ENABLED" && bs.Value == "1" {
			return []error{}
		}
	}
	return []error{fmt.Errorf("not compiled with CGO_ENABLED=1")}
}

func validateCgoInit(info *elfinfo.ElfInfo) []error {
	for _, sym := range info.Symbols {
		if sym.Section >= elf.SHN_LORESERVE || int(sym.Section) >= len(info.Sections) {
			continue
		}
		section := info.Sections[sym.Section]
		if (sym.Name == "_cgo_init" || sym.Name == "_cgo_topofstack") && !slices.Contains([]string{".bss"}, section) {
			return []error{}
		}
	}
	return []error{fmt.Errorf("missing cgo_init symbol")}
}

func validateGoSymbols(info *elfinfo.ElfInfo, goVersion *semver.Version) []error {
	var requiredSymbols []string
	for _, req := range requiredSymbolsForGoVersions {
		if req.versions.Check(goVersion) {
			requiredSymbols = req.requirements
			break
		}
	}
	if len(requiredSymbols) == 0 {
		return []error{fmt.Errorf("uses Go version %s, which is not yet supported by fips-validator", goVersion)}
	}

	var errs []error
	for _, rs := range requiredSymbols {
		found := false
		for _, sym := range info.Symbols {
			if sym.Section >= elf.SHN_LORESERVE || int(sym.Section) >= len(info.Sections) {
				continue
			}
			section := info.Sections[sym.Section]
			if sym.Name == rs && !slices.Contains([]string{".bss"}, section) {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("missing required symbol %q", rs))
		}
	}
	return errs
}

func validateGoTagsAndExperiment(info *buildinfo.BuildInfo) []error {
	var errs []error

	buildTags := []string{}
	for _, bs := range info.Settings {
		if bs.Key == "-tags" {
			buildTags = strings.Split(bs.Value, ",")
			break
		}
	}
	deniedTags := []string{"no_openssl"}
	for _, tag := range deniedTags {
		if slices.Contains(buildTags, tag) {
			errs = append(errs, fmt.Errorf("uses forbidden build tag %v", tag))
		}
	}

	strict := false
	for _, bs := range info.Settings {
		if bs.Key == "GOEXPERIMENT" {
			for _, experiment := range strings.Split(bs.Value, ",") {
				switch experiment {
				case "strictfipsruntime":
					strict = true
				case "none", "nostrictfipsruntime":
					strict = false
				}
			}
		}
	}
	if !strict {
		errs = append(errs, fmt.Errorf("missing required GOEXPERIMENT value 'strictfipsruntime'"))
	}

	return errs
}

func validateGoBackend(info *buildinfo.BuildInfo, goVersion *semver.Version) []error {
	snapshot := ""
	for _, setting := range info.Settings {
		if setting.Key == "GOFIPS140" {
			snapshot = setting.Value
		}
	}
	if newSemverConstraint(">= 1.27, < 1.28").Check(goVersion) {
		if snapshot != "v1.0.0-c2097c7c" {
			return []error{fmt.Errorf("unsupported native FIPS snapshot %q; require GOFIPS140=v1.0.0-c2097c7c", snapshot)}
		}
	} else if snapshot != "" && snapshot != "off" {
		return []error{fmt.Errorf("native FIPS snapshot is unsupported for Go %s", goVersion)}
	}
	return nil
}
