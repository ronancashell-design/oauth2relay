// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLicenseHeaders checks that every source file in the repository
// starts with the SPDX licence identifier and the copyright line
// (CONTRIBUTING.md).
func TestLicenseHeaders(t *testing.T) {
	const root = "../.."
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "web" || name == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(name) {
		case ".go", ".sh":
			files = append(files, path)
		case ".py":
			if filepath.Base(filepath.Dir(path)) == "test_scripts" {
				files = append(files, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no source files found")
	}
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), "._") {
			continue // macOS resource forks
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitN(string(data), "\n", 4)
		if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
			lines = lines[1:]
		}
		if len(lines) < 2 ||
			!strings.HasSuffix(lines[0], " SPDX-License-Identifier: Apache-2.0") ||
			!strings.HasSuffix(lines[1], " Copyright 2024-2026 Fijomi Systems SL") {
			t.Errorf("%s: must start with the SPDX-License-Identifier and Copyright lines", f)
		}
	}
}
