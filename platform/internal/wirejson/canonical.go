package wirejson

import (
	"bytes"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonical returns RFC 8785 JCS bytes after strict SDK JSON admission.
// Callers must keep admitted original bytes separately when a wire digest or
// later strict parse depends on their number tokens or lexical spelling.
func Canonical(raw []byte, limit int) ([]byte, error) {
	if len(raw) > limit || Validate(raw, limit) != nil {
		return nil, ErrInvalidJSON
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil, ErrInvalidJSON
	}
	var out bytes.Buffer
	var emit func(any)
	quote := func(s string) {
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\t':
				out.WriteString(`\t`)
			case '\n':
				out.WriteString(`\n`)
			case '\f':
				out.WriteString(`\f`)
			case '\r':
				out.WriteString(`\r`)
			default:
				if r < 0x20 {
					out.WriteString(`\u00`)
					out.WriteByte("0123456789abcdef"[r>>4])
					out.WriteByte("0123456789abcdef"[r&15])
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	}
	emit = func(v any) {
		switch x := v.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			if x {
				out.WriteString("true")
			} else {
				out.WriteString("false")
			}
		case string:
			quote(x)
		case float64:
			if x == 0 {
				out.WriteByte('0')
				return
			}
			format := byte('f')
			if math.Abs(x) < 1e-6 || math.Abs(x) >= 1e21 {
				format = 'e'
			}
			n := strconv.FormatFloat(x, format, -1, 64)
			// ECMAScript omits the exponent's redundant leading zero.
			n = strings.Replace(n, "e-0", "e-", 1)
			n = strings.Replace(n, "e+0", "e+", 1)
			out.WriteString(n)
		case []any:
			out.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					out.WriteByte(',')
				}
				emit(item)
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			slices.SortFunc(keys, func(a, b string) int { return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) })
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				quote(k)
				out.WriteByte(':')
				emit(x[k])
			}
			out.WriteByte('}')
		}
	}
	emit(value)
	if out.Len() > limit {
		return nil, ErrInvalidJSON
	}
	return out.Bytes(), nil
}
