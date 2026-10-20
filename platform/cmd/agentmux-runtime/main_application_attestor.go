//go:build linux || darwin

package main

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

type singleApplicationFlag struct {
	value   *string
	present bool
}

func (value *singleApplicationFlag) String() string { return "explicit private application selection" }
func (value *singleApplicationFlag) Set(text string) error {
	if value.present {
		return errors.New("arguments_invalid")
	}
	*value.value, value.present = text, true
	return nil
}

func validateApplicationFlags(o options, pathPresent, digestPresent bool) error {
	if !pathPresent && !digestPresent {
		return nil
	}
	if !pathPresent || !digestPresent || (o.operation != "ensure" && o.operation != "host") || !filepath.IsAbs(o.applicationSelection) || filepath.Clean(o.applicationSelection) != o.applicationSelection || len(o.applicationSelection) > 4096 || strings.IndexFunc(o.applicationSelection, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(o.applicationDigest) {
		return errors.New("arguments_invalid")
	}
	return nil
}
