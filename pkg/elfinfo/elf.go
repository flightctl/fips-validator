package elfinfo

import (
	"debug/elf"
)

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
		info.Symbols, _ = exe.Symbols()
	case elf.ET_DYN: // Either a binary or a shared object.
		pie, err := isPie(exe)
		if err != nil || !pie {
			return info, err
		}
		info.IsElf = true
		info.IsStatic = isStatic(exe)
		info.Sections = getSectionNames(exe)
		info.Symbols, _ = exe.Symbols()
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
