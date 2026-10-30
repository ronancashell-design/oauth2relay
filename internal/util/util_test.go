// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package util

import (
	"strings"
	"testing"
)

func FuzzSubstitute(f *testing.F) {
	for _, seed := range []string{
		"Bearer ${ACCESSTOKEN}", "${IP}", "${", "}", "${}", "${${ACCESSTOKEN}}", "$${ACCESSTOKEN}",
		"a=${ACCESSTOKEN}&b=${ACCESSTOKEN}", "${vault:x:y}", "plain text",
	} {
		f.Add(seed, "tok-123")
	}
	f.Fuzz(func(t *testing.T, s, token string) {
		out := Substitute(s, map[string]string{"ACCESSTOKEN": token})
		if !strings.Contains(s, "${ACCESSTOKEN}") && out != s {
			t.Fatalf("Substitute(%q) = %q, but nothing should change", s, out)
		}
	})
}
