package validation

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
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
			versions: newSemverConstraint(">= 1.23"),
			requirements: []string{
				"vendor/github.com/golang-fips/openssl/v2.dlopen",
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

	ei, err := elfinfo.ReadFile(filepath.Join(rootPath, path))
	if err != nil {
		if strings.HasPrefix(err.Error(), "bad magic number '[35 33") {
			fmt.Printf("skipped (shell script)\n")
		} else {
			fmt.Printf("skipped (failed to read ELF info: %v)\n", err)
		}
		return true // Skip is considered success
	}
	if !ei.IsElf {
		fmt.Printf("skipped (not an ELF executable)\n")
		return true // Skip is considered success
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

	for _, bs := range info.Settings {
		if bs.Key == "GOEXPERIMENT" && !strings.Contains(bs.Value, "strictfipsruntime") {
			errs = append(errs, fmt.Errorf("missing required GOEXPERIMENT value 'strictfipsruntime'"))
		}
	}

	return errs
}
