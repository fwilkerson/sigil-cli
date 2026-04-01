package trust

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ParamShapes converts a parameter map into a type-shape representation
// suitable for inclusion in negative attestation claims. Raw values are
// replaced with type descriptors to protect PII.
//
// Examples:
//
//	{"name": "Alice", "count": 42}  →  {"count": "<int>", "name": "<string>"}
//	{"items": [1, 2, 3]}           →  {"items": "<array[3]>"}
//	{"nested": {"a": 1}}           →  {"nested": "<object>"}
func ParamShapes(params map[string]any) string {
	if len(params) == 0 {
		return "{}"
	}

	shapes := make(map[string]string, len(params))
	for k, v := range params {
		shapes[k] = typeShape(v)
	}

	// encoding/json sorts string map keys lexicographically.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(shapes); err != nil {
		return "{}"
	}
	// Encode appends a newline; trim it.
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// typeShape returns a type descriptor for a single value.
func typeShape(v any) string {
	switch val := v.(type) {
	case nil:
		return "<null>"
	case bool:
		return "<bool>"
	case string:
		return "<string>"
	case float64:
		// JSON numbers decode to float64 by default.
		if val == float64(int64(val)) {
			return "<int>"
		}
		return "<float>"
	case json.Number:
		if _, err := val.Int64(); err == nil {
			return "<int>"
		}
		return "<float>"
	case []any:
		return fmt.Sprintf("<array[%d]>", len(val))
	case map[string]any:
		return "<object>"
	default:
		return "<unknown>"
	}
}
