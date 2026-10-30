// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package util holds small helpers shared by the oauth2relay packages.
package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

// varRe matches a runtime variable such as ${ACCESSTOKEN}.
var varRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// Substitute replaces ${VARNAME} in the target string with the
// corresponding value from vars.
func Substitute(target string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(target, func(match string) string {
		keyMatch := varRe.FindStringSubmatch(match)
		if len(keyMatch) > 1 {
			if val, ok := vars[keyMatch[1]]; ok {
				return val
			}
		}
		return match
	})
}

// ToString returns a JSON string or number as a string.
func ToString(v interface{}) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), true
	default:
		return "", false
	}
}

// ToFloat64 returns a JSON number, or a string holding one, as a float64.
func ToFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert to float64")
	}
}

// RandomID returns 32 random hex characters.
func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
