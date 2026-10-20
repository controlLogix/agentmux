// Package wirejson implements the SDK JSON admission and RFC 8785 wire codec.
// Parsing and canonicalization never establish authentication or authority.
package wirejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalidJSON = errors.New("wire_json_invalid")

// Validate refuses duplicate keys, invalid Unicode, excessive nesting, unsafe
// integer tokens and non-finite binary64 values within the caller's byte limit.
func Validate(raw []byte, limit int) error {
	if limit <= 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrInvalidJSON
	}
	// encoding/json replaces lone surrogate escapes; refuse them before decoding.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for ; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if i >= len(raw) {
				return ErrInvalidJSON
			}
			if raw[i] != 'u' {
				continue
			}
			if i+4 >= len(raw) {
				return ErrInvalidJSON
			}
			n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if e != nil {
				return ErrInvalidJSON
			}
			i += 4
			if n >= 0xDC00 && n <= 0xDFFF {
				return ErrInvalidJSON
			}
			if n >= 0xD800 && n <= 0xDBFF {
				if i+6 >= len(raw) || string(raw[i+1:i+3]) != "\\u" {
					return ErrInvalidJSON
				}
				lo, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if e != nil || lo < 0xDC00 || lo > 0xDFFF {
					return ErrInvalidJSON
				}
				i += 6
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case json.Delim:
			if depth >= 64 {
				return ErrInvalidJSON
			}
			switch t {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return e
					}
					k, ok := key.(string)
					if !ok || seen[k] {
						return ErrInvalidJSON
					}
					seen[k] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return ErrInvalidJSON
			}
			_, err = d.Token()
			return err
		case json.Number:
			if strings.ContainsAny(string(t), ".eE") {
				value, err := strconv.ParseFloat(string(t), 64)
				if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
					return ErrInvalidJSON
				}
				return nil
			}
			n, e := strconv.ParseInt(string(t), 10, 64)
			if e != nil || n > 9007199254740991 || n < -9007199254740991 {
				return ErrInvalidJSON
			}
		}
		return nil
	}
	if walk(0) != nil {
		return ErrInvalidJSON
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidJSON
	}
	return nil
}
