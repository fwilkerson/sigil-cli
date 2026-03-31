package trustclient

import "testing"

func TestParamShapes(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{
			name:   "nil params",
			params: nil,
			want:   "{}",
		},
		{
			name:   "empty params",
			params: map[string]any{},
			want:   "{}",
		},
		{
			name:   "string value",
			params: map[string]any{"name": "Alice"},
			want:   `{"name":"<string>"}`,
		},
		{
			name:   "int value",
			params: map[string]any{"count": float64(42)},
			want:   `{"count":"<int>"}`,
		},
		{
			name:   "float value",
			params: map[string]any{"ratio": float64(3.14)},
			want:   `{"ratio":"<float>"}`,
		},
		{
			name:   "bool value",
			params: map[string]any{"enabled": true},
			want:   `{"enabled":"<bool>"}`,
		},
		{
			name:   "null value",
			params: map[string]any{"empty": nil},
			want:   `{"empty":"<null>"}`,
		},
		{
			name:   "array value",
			params: map[string]any{"items": []any{1, 2, 3}},
			want:   `{"items":"<array[3]>"}`,
		},
		{
			name:   "object value",
			params: map[string]any{"nested": map[string]any{"a": 1}},
			want:   `{"nested":"<object>"}`,
		},
		{
			name: "mixed types sorted by key",
			params: map[string]any{
				"name":  "Bob",
				"count": float64(5),
				"items": []any{"a", "b"},
			},
			want: `{"count":"<int>","items":"<array[2]>","name":"<string>"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParamShapes(tt.params)
			if got != tt.want {
				t.Errorf("ParamShapes() = %q, want %q", got, tt.want)
			}
		})
	}
}
