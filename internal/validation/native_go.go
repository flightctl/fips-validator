package validation

import (
	"debug/buildinfo"
	"fmt"
	"slices"
	"strings"

	"github.com/flightctl/fips-validator/pkg/elfinfo"
)

// Accept the certified v1.0.0 snapshot and its Red Hat distribution identifier.
// New snapshots require review against their CMVP certificate before inclusion.
func validateNativeGo(info *buildinfo.BuildInfo, elfInfo *elfinfo.ElfInfo) []error {
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	var errs []error
	switch settings["GOFIPS140"] {
	case "v1.0.0", "v1.0.0-c2097c7c":
	default:
		errs = append(errs, fmt.Errorf("native Go binary does not select a supported certified FIPS module: GOFIPS140=%q", settings["GOFIPS140"]))
	}
	mode := ""
	for _, setting := range strings.Split(settings["DefaultGODEBUG"], ",") {
		if value, ok := strings.CutPrefix(setting, "fips140="); ok {
			mode = value
		}
	}
	if !slices.Contains([]string{"on", "auto", "only"}, mode) {
		errs = append(errs, fmt.Errorf("native Go binary does not enable FIPS by default or on FIPS hosts: fips140=%q", mode))
	}
	if !slices.Contains(elfInfo.Sections, ".go.fipsinfo") {
		errs = append(errs, fmt.Errorf("native Go binary is missing the FIPS integrity-check section"))
	}
	return errs
}
