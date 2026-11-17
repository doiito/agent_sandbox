package main

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func apiGoModules(binary, vendorDir, noticesPath string) ([]component, error) {
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return nil, err
	}
	if len(info.Deps) == 0 {
		return nil, errors.New("API binary has no Go module dependency records")
	}
	manifest, err := os.ReadFile(filepath.Join(vendorDir, "modules.txt"))
	if err != nil {
		return nil, err
	}
	versions := make(map[string]string)
	for _, line := range strings.Split(string(manifest), "\n") {
		header, ok := strings.CutPrefix(line, "# ")
		if fields := strings.Fields(header); ok && len(fields) == 2 {
			versions[fields[0]] = fields[1]
		}
	}
	sort.Slice(info.Deps, func(i, j int) bool { return info.Deps[i].Path < info.Deps[j].Path })
	var notices bytes.Buffer
	fmt.Fprintf(&notices, "Go modules linked into osv-sandboxd (%s)\n", info.GoVersion)
	components := make([]component, 0, len(info.Deps))
	for _, module := range info.Deps {
		if !fs.ValidPath(module.Path) || module.Replace != nil || versions[module.Path] != module.Version {
			return nil, fmt.Errorf("linked module %s %s does not match the vendor manifest", module.Path, module.Version)
		}
		entry := component{Type: "library", Name: module.Path, Version: module.Version, PURL: "pkg:golang/" + module.Path + "@" + module.Version}
		for _, name := range []string{"LICENSE", "PATENTS", "NOTICE", "NOTICE.txt"} {
			text, err := os.ReadFile(filepath.Join(vendorDir, filepath.FromSlash(module.Path), name))
			if name != "LICENSE" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if len(bytes.TrimSpace(text)) == 0 {
				return nil, fmt.Errorf("empty %s for linked module %s", name, module.Path)
			}
			fmt.Fprintf(&notices, "\n=== %s %s / %s ===\n\n", module.Path, module.Version, name)
			notices.Write(text)
			if !bytes.HasSuffix(text, []byte("\n")) {
				notices.WriteByte('\n')
			}
			if name == "LICENSE" {
				entry.Licenses = []licenseChoice{{License: &licenseText{Name: module.Path + " LICENSE",
					Text: &attachedText{ContentType: "text/plain", Content: string(text)}}}}
			}
		}
		components = append(components, entry)
	}
	if err := os.WriteFile(noticesPath, notices.Bytes(), 0o644); err != nil {
		return nil, err
	}
	return components, nil
}
