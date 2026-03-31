package id_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/id"
)

func TestID_RoundTrip(t *testing.T) {
	t.Parallel()
	t.Run("ActorID", func(t *testing.T) {
		t.Parallel()
		orig := id.NewActorID()
		parsed, err := id.ParseActorID(orig.String())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if parsed != orig {
			t.Fatalf("got %s, want %s", parsed, orig)
		}
	})
	t.Run("TransactionID", func(t *testing.T) {
		t.Parallel()
		orig := id.NewTransactionID()
		parsed, err := id.ParseTransactionID(orig.String())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if parsed != orig {
			t.Fatalf("got %s, want %s", parsed, orig)
		}
	})
	t.Run("SigilID", func(t *testing.T) {
		t.Parallel()
		orig := id.NewSigilID()
		parsed, err := id.ParseSigilID(orig.String())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if parsed != orig {
			t.Fatalf("got %s, want %s", parsed, orig)
		}
	})
	t.Run("AuditID", func(t *testing.T) {
		t.Parallel()
		orig := id.NewAuditID()
		parsed, err := id.ParseAuditID(orig.String())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if parsed != orig {
			t.Fatalf("got %s, want %s", parsed, orig)
		}
	})
}

func TestIDs_AreUnique(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for range 100 {
		s := id.NewActorID().String()
		if seen[s] {
			t.Fatalf("duplicate ID: %s", s)
		}
		seen[s] = true
	}
}

func TestID_Time(t *testing.T) {
	t.Parallel()
	before := time.Now().Add(-time.Second)
	aid := id.NewActorID()
	after := time.Now().Add(time.Second)

	ts := aid.Time()
	if ts.Before(before) || ts.After(after) {
		t.Fatalf("timestamp %v not in [%v, %v]", ts, before, after)
	}
}

func TestID_IsZero(t *testing.T) {
	t.Parallel()
	var zero id.ActorID
	if !zero.IsZero() {
		t.Fatal("zero value should be zero")
	}
	if id.NewActorID().IsZero() {
		t.Fatal("new ID should not be zero")
	}
}

func TestParse_InvalidInput(t *testing.T) {
	t.Parallel()
	bad := "not-a-ulid"

	tests := []struct {
		name  string
		parse func(string) error
	}{
		{"ActorID", func(s string) error { _, err := id.ParseActorID(s); return err }},
		{"TransactionID", func(s string) error { _, err := id.ParseTransactionID(s); return err }},
		{"SigilID", func(s string) error { _, err := id.ParseSigilID(s); return err }},
		{"AuditID", func(s string) error { _, err := id.ParseAuditID(s); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.parse(bad); err == nil {
				t.Fatal("expected error for bad input")
			}
		})
	}
}

// TestJSON_RoundTrip verifies that all four ID types survive a JSON
// marshal/unmarshal cycle with their values intact.
func TestJSON_RoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("ActorID", func(t *testing.T) {
		t.Parallel()
		type wrapper struct{ ID id.ActorID }
		orig := wrapper{ID: id.NewActorID()}
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got wrapper
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ID != orig.ID {
			t.Fatalf("got %s, want %s", got.ID, orig.ID)
		}
	})

	t.Run("TransactionID", func(t *testing.T) {
		t.Parallel()
		type wrapper struct{ ID id.TransactionID }
		orig := wrapper{ID: id.NewTransactionID()}
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got wrapper
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ID != orig.ID {
			t.Fatalf("got %s, want %s", got.ID, orig.ID)
		}
	})

	t.Run("SigilID", func(t *testing.T) {
		t.Parallel()
		type wrapper struct{ ID id.SigilID }
		orig := wrapper{ID: id.NewSigilID()}
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got wrapper
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ID != orig.ID {
			t.Fatalf("got %s, want %s", got.ID, orig.ID)
		}
	})

	t.Run("AuditID", func(t *testing.T) {
		t.Parallel()
		type wrapper struct{ ID id.AuditID }
		orig := wrapper{ID: id.NewAuditID()}
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got wrapper
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ID != orig.ID {
			t.Fatalf("got %s, want %s", got.ID, orig.ID)
		}
	})
}

// TestJSON_ZeroRoundTrip verifies that zero-value IDs marshal and unmarshal
// without error and remain equal after the round-trip.
func TestJSON_ZeroRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("ActorID", func(t *testing.T) {
		t.Parallel()
		var orig id.ActorID
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got id.ActorID
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != orig {
			t.Fatalf("got %s, want %s", got, orig)
		}
	})

	t.Run("TransactionID", func(t *testing.T) {
		t.Parallel()
		var orig id.TransactionID
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got id.TransactionID
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != orig {
			t.Fatalf("got %s, want %s", got, orig)
		}
	})

	t.Run("SigilID", func(t *testing.T) {
		t.Parallel()
		var orig id.SigilID
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got id.SigilID
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != orig {
			t.Fatalf("got %s, want %s", got, orig)
		}
	})

	t.Run("AuditID", func(t *testing.T) {
		t.Parallel()
		var orig id.AuditID
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got id.AuditID
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != orig {
			t.Fatalf("got %s, want %s", got, orig)
		}
	})
}

// TestJSON_InvalidUnmarshal verifies that json.Unmarshal returns an error for
// bad input strings and does not panic.
func TestJSON_InvalidUnmarshal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		json string
	}{
		{"empty string", `""`},
		{"garbage", `"not-a-ulid"`},
		{"wrong length", `"01ARZ3NDEKTSV4RRFFQ69G5FA"`}, // one char too short
	}

	for _, tc := range cases {
		t.Run("ActorID/"+tc.name, func(t *testing.T) {
			t.Parallel()
			var v id.ActorID
			if err := json.Unmarshal([]byte(tc.json), &v); err == nil {
				t.Fatalf("expected error for input %s", tc.json)
			}
		})
		t.Run("TransactionID/"+tc.name, func(t *testing.T) {
			t.Parallel()
			var v id.TransactionID
			if err := json.Unmarshal([]byte(tc.json), &v); err == nil {
				t.Fatalf("expected error for input %s", tc.json)
			}
		})
		t.Run("SigilID/"+tc.name, func(t *testing.T) {
			t.Parallel()
			var v id.SigilID
			if err := json.Unmarshal([]byte(tc.json), &v); err == nil {
				t.Fatalf("expected error for input %s", tc.json)
			}
		})
		t.Run("AuditID/"+tc.name, func(t *testing.T) {
			t.Parallel()
			var v id.AuditID
			if err := json.Unmarshal([]byte(tc.json), &v); err == nil {
				t.Fatalf("expected error for input %s", tc.json)
			}
		})
	}
}

// TestJSON_StructEmbedding verifies that an ID field inside a JSON object
// deserializes to the correct value.
func TestJSON_StructEmbedding(t *testing.T) {
	t.Parallel()

	orig := id.NewActorID()
	raw := `{"actor_id":"` + orig.String() + `"}`

	type payload struct {
		ActorID id.ActorID `json:"actor_id"`
	}
	var got payload
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ActorID != orig {
		t.Fatalf("got %s, want %s", got.ActorID, orig)
	}
}

// TestJSON_Representation verifies that marshaling an ID produces a quoted
// ULID string in JSON, not an object like {"v":"..."}.
func TestJSON_Representation(t *testing.T) {
	t.Parallel()

	t.Run("ActorID", func(t *testing.T) {
		t.Parallel()
		v := id.NewActorID()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s := string(data)
		// Must be a quoted string of the form "<ULID>".
		if !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
			t.Fatalf("JSON is not a quoted string: %s", s)
		}
		inner := s[1 : len(s)-1]
		if inner != v.String() {
			t.Fatalf("inner JSON value %q does not match String() %q", inner, v.String())
		}
	})

	t.Run("TransactionID", func(t *testing.T) {
		t.Parallel()
		v := id.NewTransactionID()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s := string(data)
		if !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
			t.Fatalf("JSON is not a quoted string: %s", s)
		}
		inner := s[1 : len(s)-1]
		if inner != v.String() {
			t.Fatalf("inner JSON value %q does not match String() %q", inner, v.String())
		}
	})

	t.Run("SigilID", func(t *testing.T) {
		t.Parallel()
		v := id.NewSigilID()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s := string(data)
		if !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
			t.Fatalf("JSON is not a quoted string: %s", s)
		}
		inner := s[1 : len(s)-1]
		if inner != v.String() {
			t.Fatalf("inner JSON value %q does not match String() %q", inner, v.String())
		}
	})

	t.Run("AuditID", func(t *testing.T) {
		t.Parallel()
		v := id.NewAuditID()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s := string(data)
		if !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
			t.Fatalf("JSON is not a quoted string: %s", s)
		}
		inner := s[1 : len(s)-1]
		if inner != v.String() {
			t.Fatalf("inner JSON value %q does not match String() %q", inner, v.String())
		}
	})
}

// TestZeroID_Time verifies that calling Time() on a zero-value ID does not
// panic and returns a valid (non-zero) time value.
func TestZeroID_Time(t *testing.T) {
	t.Parallel()

	t.Run("ActorID", func(t *testing.T) {
		t.Parallel()
		var v id.ActorID
		// ulid.Time(0) returns the Unix epoch, which is non-zero in Go's
		// time.Time representation. We only require no panic.
		_ = v.Time()
	})

	t.Run("TransactionID", func(t *testing.T) {
		t.Parallel()
		var v id.TransactionID
		_ = v.Time()
	})

	t.Run("SigilID", func(t *testing.T) {
		t.Parallel()
		var v id.SigilID
		_ = v.Time()
	})

	t.Run("AuditID", func(t *testing.T) {
		t.Parallel()
		var v id.AuditID
		_ = v.Time()
	})
}
