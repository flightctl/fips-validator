package elfinfo

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
)

// ErrSymbols identifies an executable whose symbol information cannot be read.
var ErrSymbols = errors.New("failed to read executable symbols")

type ElfInfo struct {
	IsElf    bool
	IsStatic bool
	Sections []string
	Symbols  []elf.Symbol
}

func ReadFile(path string) (*ElfInfo, error) {
	exe, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer exe.Close()

	info := &ElfInfo{}
	switch exe.Type {
	case elf.ET_EXEC:
		info.IsElf = true
		info.IsStatic = isStatic(exe)
		info.Sections = getSectionNames(exe)
	case elf.ET_DYN: // Either a binary or a shared object.
		pie, err := isPie(exe)
		if err != nil || !pie {
			return info, err
		}
		info.IsElf = true
		info.IsStatic = isStatic(exe)
		info.Sections = getSectionNames(exe)
	}
	if info.IsElf {
		info.Symbols, err = readSymbols(exe)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSymbols, err)
		}
	}
	return info, nil
}

// isStatic returns whether an ELF executable is a statically-linked binary.
func isStatic(exe *elf.File) bool {
	for _, p := range exe.Progs {
		// Static binaries do not have a PT_INTERP program.
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	return true
}

// isPie returns whether an ELF executable is a position-independent executable.
func isPie(file *elf.File) (bool, error) {
	vals, err := file.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		return false, err
	}
	for _, f := range vals {
		if elf.DynFlag1(f)&elf.DF_1_PIE != 0 {
			return true, nil
		}
	}
	return false, nil
}

func getSectionNames(file *elf.File) []string {
	sectionNames := make([]string, len(file.Sections))
	for i, s := range file.Sections {
		sectionNames[i] = s.Name
	}
	return sectionNames
}

// Stripped Go binaries retain their function table. Use it for crypto detection
// so removing the ELF symbol table cannot bypass validation.
func readSymbols(file *elf.File) ([]elf.Symbol, error) {
	symbols, err := file.Symbols()
	if err == nil && len(symbols) > 0 {
		return symbols, nil
	}
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("read ELF symbol table: %w", err)
	}
	// A stripped binary has no regular symbol table. Go's function table is
	// required to classify its crypto use; a failure must not imply no crypto.
	pcln := file.Section(".gopclntab")
	if pcln == nil {
		pcln = file.Section(".data.rel.ro.gopclntab")
	}
	if pcln == nil {
		if file.Section(".go.buildinfo") == nil && file.Section(".note.go.buildid") == nil {
			// Stripped non-Go executables have no Go function table. Retain
			// their existing handling when the regular symbol table is absent.
			return nil, nil
		}
		return nil, fmt.Errorf("Go executable is missing its function table")
	}
	text := file.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("Go executable is missing its text section")
	}
	data, err := pcln.Data()
	if err != nil {
		return nil, fmt.Errorf("read Go function table: %w", err)
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return nil, fmt.Errorf("parse Go function table: %w", err)
	}
	if len(table.Funcs) == 0 {
		return nil, fmt.Errorf("Go function table contains no functions")
	}
	var index elf.SectionIndex
	for i, section := range file.Sections {
		if section == text {
			index = elf.SectionIndex(i)
			break
		}
	}
	for _, fn := range table.Funcs {
		symbols = append(symbols, elf.Symbol{Name: fn.Name, Section: index})
	}
	return symbols, nil
}
