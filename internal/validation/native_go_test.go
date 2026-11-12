package validation

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/flightctl/fips-validator/pkg/elfinfo"
)

func TestValidateNativeGo(t *testing.T) {
	tests := []struct {
		name, module, mode string
		integrity, valid   bool
	}{
		{"When the certified module is selected it should accept static native crypto", "v1.0.0", "on", true, true},
		{"When Red Hat host detection is selected it should accept the certified snapshot", "v1.0.0-c2097c7c", "auto", true, true},
		{"When strict testing is selected it should accept native crypto", "v1.0.0", "only", true, true},
		{"When crypto is disabled it should reject the binary", "off", "on", true, false},
		{"When the module is not certified it should reject the binary", "latest", "on", true, false},
		{"When the selector is unresolved it should reject the binary", "certified", "on", true, false},
		{"When runtime FIPS defaults off it should reject the binary", "v1.0.0", "off", true, false},
		{"When runtime mode is missing it should reject the binary", "v1.0.0", "", true, false},
		{"When integrity information is absent it should reject the binary", "v1.0.0", "on", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &buildinfo.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOFIPS140", Value: tt.module}, {Key: "DefaultGODEBUG", Value: "other=1,fips140=" + tt.mode}}}
			elfInfo := &elfinfo.ElfInfo{IsElf: true, IsStatic: true}
			if tt.integrity {
				elfInfo.Sections = []string{".go.fipsinfo"}
			}
			if errs := validateNativeGo(info, elfInfo); (len(errs) == 0) != tt.valid {
				t.Fatalf("valid=%t, errors=%v", tt.valid, errs)
			}
		})
	}
}

func TestParseGoVersion(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"standard release", "go1.27.3", "1.27.3"},
		{"Red Hat toolchain suffix", "go1.26.8-X:nodwarf5", "1.26.8"},
		{"release description", "go1.27.3 (Red Hat 1.27.3-1)", "1.27.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := parseGoVersion(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if got := version.String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func requireNativeGoToolchain(t *testing.T) {
	t.Helper()
	version, err := parseGoVersion(runtime.Version())
	if err != nil || version.Major() != 1 || version.Minor() < 27 {
		t.Skipf("requires Go 1.27 or newer, running %q", runtime.Version())
	}
}

func TestNativeGoBinary(t *testing.T) {
	requireNativeGoToolchain(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte(`package main
import("crypto/sha256"; "fmt")
func main(){fmt.Println(sha256.Sum256([]byte("fips"))) }
`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"v1.0.0", "off"} {
		t.Run(module, func(t *testing.T) {
			binary := filepath.Join(dir, "probe-"+module)
			cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", binary, source)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFIPS140="+module)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build probe: %v: %s", err, output)
			}
			valid := ValidateBinary(context.Background(), "", binary, t.Logf)
			if valid != (module == "v1.0.0") {
				t.Fatalf("module %s: validation=%t", module, valid)
			}
		})
	}
}

func TestNativeGoMalformedSymbols(t *testing.T) {
	requireNativeGoToolchain(t)
	for _, mode := range []string{"exe", "pie"} {
		t.Run(mode, func(t *testing.T) { testNativeGoMalformedSymbols(t, mode) })
	}
}

func testNativeGoMalformedSymbols(t *testing.T, mode string) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte(`package main
import("crypto/sha256"; "fmt")
func main(){fmt.Println(sha256.Sum256([]byte("fips")))}
`), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-buildmode="+mode, "-ldflags=-s -w", "-o", binary, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFIPS140=v1.0.0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v: %s", err, output)
	}
	if !ValidateBinary(context.Background(), "", binary, t.Logf) {
		t.Fatal("valid stripped Go fixture was rejected")
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	order, class := file.ByteOrder, file.Class
	pcln := file.Section(".gopclntab")
	if pcln == nil {
		pcln = file.Section(".data.rel.ro.gopclntab")
	}
	var pclnIndex, textIndex int
	for i, section := range file.Sections {
		switch section.Name {
		case ".gopclntab", ".data.rel.ro.gopclntab":
			pclnIndex = i
		case ".text":
			textIndex = i
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if class != elf.ELFCLASS64 {
		t.Skip("ELF corruption fixture requires ELF64")
	}
	if pcln == nil || pclnIndex == 0 || textIndex == 0 {
		t.Fatal("Go fixture is missing expected ELF sections")
	}
	// ELF64 e_shoff/e_shentsize locate section headers; sh_name and sh_offset
	// select a section's name and data independently of its contents.
	sectionHeaders := order.Uint64(data[40:48])
	sectionSize := uint64(order.Uint16(data[58:60]))
	pclnHeader := sectionHeaders + uint64(pclnIndex)*sectionSize
	textHeader := sectionHeaders + uint64(textIndex)*sectionSize
	tests := []struct {
		name    string
		corrupt func([]byte)
	}{
		{"When the function-table header is corrupt it should reject the binary", func(b []byte) { clear(b[pcln.Offset : pcln.Offset+8]) }},
		{"When the function table is unreadable it should reject the binary", func(b []byte) { order.PutUint64(b[pclnHeader+24:pclnHeader+32], uint64(len(b))+4096) }},
		{"When the function table is missing it should reject the binary", func(b []byte) { order.PutUint32(b[pclnHeader:pclnHeader+4], 0) }},
		{"When the text section is missing it should reject the binary", func(b []byte) { order.PutUint32(b[textHeader:textHeader+4], 0) }},
		{"When the function table is empty it should reject the binary", func(b []byte) { clear(b[pcln.Offset+8 : pcln.Offset+16]) }},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			damaged := append([]byte(nil), data...)
			tt.corrupt(damaged)
			path := filepath.Join(dir, fmt.Sprintf("damaged-%d", i))
			if err := os.WriteFile(path, damaged, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := elfinfo.ReadFile(path); !errors.Is(err, elfinfo.ErrSymbols) {
				t.Fatalf("expected symbol-loading error, got %v", err)
			}
			if ValidateBinary(context.Background(), "", path, t.Logf) {
				t.Fatal("malformed Go binary was accepted")
			}
		})
	}
}
