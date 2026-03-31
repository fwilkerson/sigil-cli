package toolattest_test

import (
	"context"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/id"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
	"github.com/fwilkerson/sigil-cli/sigil/toolattest"
)

// helpers

func makeAttestation(t *testing.T, kp *signing.KeyPair, toolURI string, issuedAt time.Time) *toolattest.ToolAttestation {
	t.Helper()
	tool, err := id.NewToolID(toolURI)
	if err != nil {
		t.Fatalf("NewToolID(%q): %v", toolURI, err)
	}
	return &toolattest.ToolAttestation{
		ID:       id.NewToolAttestationID(),
		Attester: identity.DIDFromKey(kp.Public),
		Tool:     tool,
		Outcome:  toolattest.OutcomeSuccess,
		Claims:   map[string]string{toolattest.ClaimFunction: "search"},
		Version:  "1.0.0",
		IssuedAt: issuedAt.Truncate(time.Second),
	}
}

func mustKeyPair(t *testing.T) *signing.KeyPair {
	t.Helper()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func mustToolID(t *testing.T, uri string) id.ToolID {
	t.Helper()
	toolID, err := id.NewToolID(uri)
	if err != nil {
		t.Fatalf("NewToolID(%q): %v", uri, err)
	}
	return toolID
}

// TestPutAndGet verifies that an attestation stored with Put can be
// retrieved with Get, and that all fields round-trip correctly.
func TestPutAndGet(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	att := makeAttestation(t, kp, "mcp://github.com/user/repo", now)
	if err := store.Put(ctx, att); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, att.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.ID != att.ID {
		t.Errorf("ID: got %v, want %v", got.ID, att.ID)
	}
	if got.Attester != att.Attester {
		t.Errorf("Attester: got %v, want %v", got.Attester, att.Attester)
	}
	if got.Tool != att.Tool {
		t.Errorf("Tool: got %v, want %v", got.Tool, att.Tool)
	}
	if got.Outcome != att.Outcome {
		t.Errorf("Outcome: got %v, want %v", got.Outcome, att.Outcome)
	}
	if got.Version != att.Version {
		t.Errorf("Version: got %v, want %v", got.Version, att.Version)
	}
	if !got.IssuedAt.Equal(att.IssuedAt) {
		t.Errorf("IssuedAt: got %v, want %v", got.IssuedAt, att.IssuedAt)
	}
	if got.Claims[toolattest.ClaimFunction] != att.Claims[toolattest.ClaimFunction] {
		t.Errorf("Claims: got %v, want %v", got.Claims, att.Claims)
	}
}

// TestGet_NotFound verifies that Get returns ErrNotFound for unknown IDs.
func TestGet_NotFound(t *testing.T) {
	t.Parallel()

	store := toolattest.NewMemStore()
	ctx := context.Background()

	_, err := store.Get(ctx, id.NewToolAttestationID())
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if err != toolattest.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestPut_Idempotent verifies that re-Putting the same attestation (same ID,
// same content) returns ErrAlreadyExists.
func TestPut_Idempotent(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	att := makeAttestation(t, kp, "mcp://github.com/user/repo", now)
	if err := store.Put(ctx, att); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// Identical content — expect ErrAlreadyExists.
	if err := store.Put(ctx, att); err != toolattest.ErrAlreadyExists {
		t.Errorf("second Put with same content: got %v, want ErrAlreadyExists", err)
	}
}

// TestPut_Conflict verifies that Putting an attestation with the same ID but
// different content returns ErrConflict.
func TestPut_Conflict(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	att := makeAttestation(t, kp, "mcp://github.com/user/repo", now)
	if err := store.Put(ctx, att); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// Same ID, different outcome — expect ErrConflict.
	tampered := *att
	tampered.Outcome = toolattest.OutcomeNegative
	if err := store.Put(ctx, &tampered); err != toolattest.ErrConflict {
		t.Errorf("Put with same ID, different content: got %v, want ErrConflict", err)
	}
}

// TestListByTool_Empty verifies that ListByTool returns an empty slice when
// no attestations exist for a tool.
func TestListByTool_Empty(t *testing.T) {
	t.Parallel()

	store := toolattest.NewMemStore()
	ctx := context.Background()
	toolID := mustToolID(t, "mcp://github.com/user/repo")

	atts, tok, err := store.ListByTool(ctx, toolID, 10, "")
	if err != nil {
		t.Fatalf("ListByTool: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
}

// TestListByTool returns attestations only for the requested tool, not others.
func TestListByTool(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	toolA := mustToolID(t, "mcp://github.com/user/tool-a")
	toolB := mustToolID(t, "mcp://github.com/user/tool-b")

	// Insert 3 for toolA and 2 for toolB.
	for i := range 3 {
		att := makeAttestation(t, kp, toolA.String(), now.Add(time.Duration(i)*time.Second))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put toolA[%d]: %v", i, err)
		}
	}
	for i := range 2 {
		att := makeAttestation(t, kp, toolB.String(), now.Add(time.Duration(i)*time.Second))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put toolB[%d]: %v", i, err)
		}
	}

	atts, tok, err := store.ListByTool(ctx, toolA, 10, "")
	if err != nil {
		t.Fatalf("ListByTool: %v", err)
	}
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations for toolA, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
	for _, a := range atts {
		if a.Tool != toolA {
			t.Errorf("unexpected tool: got %v, want %v", a.Tool, toolA)
		}
	}
}

// TestListByAttester returns only attestations from the requested attester.
func TestListByAttester(t *testing.T) {
	t.Parallel()

	kpA := mustKeyPair(t)
	kpB := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	didA := identity.DIDFromKey(kpA.Public)
	didB := identity.DIDFromKey(kpB.Public)

	// 2 attestations from A, 1 from B.
	for i := range 2 {
		att := makeAttestation(t, kpA, "mcp://github.com/user/repo", now.Add(time.Duration(i)*time.Second))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put attesterA[%d]: %v", i, err)
		}
	}
	attB := makeAttestation(t, kpB, "mcp://github.com/user/repo", now)
	if err := store.Put(ctx, attB); err != nil {
		t.Fatalf("Put attesterB: %v", err)
	}

	atts, tok, err := store.ListByAttester(ctx, didA, 10, "")
	if err != nil {
		t.Fatalf("ListByAttester: %v", err)
	}
	if len(atts) != 2 {
		t.Errorf("expected 2 attestations for attesterA, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
	for _, a := range atts {
		if a.Attester != didA {
			t.Errorf("unexpected attester: got %v, want %v", a.Attester, didA)
		}
	}

	// Attester B should have exactly 1.
	attsB, _, err := store.ListByAttester(ctx, didB, 10, "")
	if err != nil {
		t.Fatalf("ListByAttester B: %v", err)
	}
	if len(attsB) != 1 {
		t.Errorf("expected 1 attestation for attesterB, got %d", len(attsB))
	}
}

// TestListByToolSince returns only attestations at or after the given time.
func TestListByToolSince(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	toolURI := "mcp://github.com/user/repo"
	toolID := mustToolID(t, toolURI)

	// Insert 5 attestations at base, base+1h, base+2h, base+3h, base+4h.
	for i := range 5 {
		att := makeAttestation(t, kp, toolURI, base.Add(time.Duration(i)*time.Hour))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// Request since base+2h — should return 3 (indices 2, 3, 4).
	since := base.Add(2 * time.Hour)
	atts, tok, err := store.ListByToolSince(ctx, toolID, since, 10, "")
	if err != nil {
		t.Fatalf("ListByToolSince: %v", err)
	}
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations since base+2h, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
	for _, a := range atts {
		if a.IssuedAt.Before(since) {
			t.Errorf("attestation issued at %v is before since=%v", a.IssuedAt, since)
		}
	}
}

// TestListByToolSince_Empty verifies that ListByToolSince returns nothing when
// no attestations match the time window.
func TestListByToolSince_Empty(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	toolURI := "mcp://github.com/user/repo"
	toolID := mustToolID(t, toolURI)

	att := makeAttestation(t, kp, toolURI, base)
	if err := store.Put(ctx, att); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// since is after the only attestation.
	future := base.Add(time.Hour)
	atts, tok, err := store.ListByToolSince(ctx, toolID, future, 10, "")
	if err != nil {
		t.Fatalf("ListByToolSince: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
}

// TestListOlderThan returns attestations issued before the given threshold.
func TestListOlderThan(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()

	base := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	// Insert 6 attestations spread across two tools, alternating ages.
	for i := range 6 {
		uri := "mcp://github.com/user/tool-a"
		if i%2 == 1 {
			uri = "mcp://github.com/user/tool-b"
		}
		att := makeAttestation(t, kp, uri, base.Add(time.Duration(i)*time.Hour))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// Threshold at base+3h — attestations at base+0h, +1h, +2h are older.
	threshold := base.Add(3 * time.Hour)
	atts, tok, err := store.ListOlderThan(ctx, threshold, 10, "")
	if err != nil {
		t.Fatalf("ListOlderThan: %v", err)
	}
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations older than threshold, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
	for _, a := range atts {
		if !a.IssuedAt.Before(threshold) {
			t.Errorf("attestation issued at %v is not before threshold %v", a.IssuedAt, threshold)
		}
	}
}

// TestListOlderThan_Empty verifies that ListOlderThan returns nothing when no
// attestations are older than the threshold.
func TestListOlderThan_Empty(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()

	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	att := makeAttestation(t, kp, "mcp://github.com/user/repo", future)
	if err := store.Put(ctx, att); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Threshold before the only attestation — should return nothing.
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	atts, tok, err := store.ListOlderThan(ctx, past, 10, "")
	if err != nil {
		t.Fatalf("ListOlderThan: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
}

// TestPagination_ListByTool verifies that ListByTool returns pages of the
// requested size and that following the page tokens yields all results.
func TestPagination_ListByTool(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	toolURI := "mcp://github.com/user/repo"
	toolID := mustToolID(t, toolURI)

	const total = 7
	for i := range total {
		att := makeAttestation(t, kp, toolURI, now.Add(time.Duration(i)*time.Second))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// Page through with limit=3.
	var all []toolattest.ToolAttestation
	pageToken := ""
	for {
		page, next, err := store.ListByTool(ctx, toolID, 3, pageToken)
		if err != nil {
			t.Fatalf("ListByTool: %v", err)
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		pageToken = next
	}

	if len(all) != total {
		t.Errorf("expected %d total, got %d after pagination", total, len(all))
	}

	// IDs must be unique (no duplicates across pages).
	seen := make(map[id.ToolAttestationID]bool, total)
	for _, a := range all {
		if seen[a.ID] {
			t.Errorf("duplicate attestation ID %v across pages", a.ID)
		}
		seen[a.ID] = true
	}
}

// TestPagination_ListByToolSince verifies cursor-based pagination works for
// time-windowed queries.
func TestPagination_ListByToolSince(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	toolURI := "mcp://github.com/user/repo"
	toolID := mustToolID(t, toolURI)

	const total = 9
	for i := range total {
		att := makeAttestation(t, kp, toolURI, base.Add(time.Duration(i)*time.Hour))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// since=base+3h → 6 results (indices 3..8). Page size 2 → 3 pages.
	since := base.Add(3 * time.Hour)
	var all []toolattest.ToolAttestation
	pageToken := ""
	for {
		page, next, err := store.ListByToolSince(ctx, toolID, since, 2, pageToken)
		if err != nil {
			t.Fatalf("ListByToolSince: %v", err)
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		pageToken = next
	}

	if len(all) != 6 {
		t.Errorf("expected 6 results, got %d", len(all))
	}
	for _, a := range all {
		if a.IssuedAt.Before(since) {
			t.Errorf("attestation issued at %v is before since=%v", a.IssuedAt, since)
		}
	}
}

// TestPagination_ListOlderThan verifies cursor-based pagination for compaction
// queries.
func TestPagination_ListOlderThan(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	const total = 8
	for i := range total {
		uri := "mcp://github.com/user/tool-a"
		if i%2 == 0 {
			uri = "mcp://github.com/user/tool-b"
		}
		att := makeAttestation(t, kp, uri, base.Add(time.Duration(i)*time.Hour))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// Threshold at base+6h → 6 older records. Page size 2 → 3 pages.
	threshold := base.Add(6 * time.Hour)
	var all []toolattest.ToolAttestation
	pageToken := ""
	for {
		page, next, err := store.ListOlderThan(ctx, threshold, 2, pageToken)
		if err != nil {
			t.Fatalf("ListOlderThan: %v", err)
		}
		all = append(all, page...)
		if next == "" {
			break
		}
		pageToken = next
	}

	if len(all) != 6 {
		t.Errorf("expected 6 results, got %d", len(all))
	}
	for _, a := range all {
		if !a.IssuedAt.Before(threshold) {
			t.Errorf("attestation issued at %v is not before threshold %v", a.IssuedAt, threshold)
		}
	}
}

// TestPut_MutationIsolation verifies that mutating the caller's struct after
// Put does not affect what is stored.
func TestPut_MutationIsolation(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	att := makeAttestation(t, kp, "mcp://github.com/user/repo", now)
	if err := store.Put(ctx, att); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Mutate after Put.
	att.Outcome = toolattest.OutcomeNegative
	att.Claims[toolattest.ClaimFunction] = "mutated"

	got, err := store.Get(ctx, att.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Outcome != toolattest.OutcomeSuccess {
		t.Errorf("stored Outcome mutated: got %v, want %v", got.Outcome, toolattest.OutcomeSuccess)
	}
	if got.Claims[toolattest.ClaimFunction] != "search" {
		t.Errorf("stored Claims mutated: got %v, want %q", got.Claims, "search")
	}
}

// TestListByAttester_Empty verifies that ListByAttester returns nothing when
// the attester has no attestations.
func TestListByAttester_Empty(t *testing.T) {
	t.Parallel()

	store := toolattest.NewMemStore()
	ctx := context.Background()

	kp := mustKeyPair(t)
	did := identity.DIDFromKey(kp.Public)

	atts, tok, err := store.ListByAttester(ctx, did, 10, "")
	if err != nil {
		t.Fatalf("ListByAttester: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(atts))
	}
	if tok != "" {
		t.Errorf("expected empty page token, got %q", tok)
	}
}

// TestPagination_DefaultLimit verifies that a zero limit falls back to the
// default page size rather than returning all results at once.
func TestPagination_DefaultLimit(t *testing.T) {
	t.Parallel()

	kp := mustKeyPair(t)
	store := toolattest.NewMemStore()
	ctx := context.Background()
	now := time.Now().UTC()

	toolURI := "mcp://github.com/user/repo"
	toolID := mustToolID(t, toolURI)

	// Insert 55 attestations — more than the default page size of 50.
	for i := range 55 {
		att := makeAttestation(t, kp, toolURI, now.Add(time.Duration(i)*time.Second))
		if err := store.Put(ctx, att); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// limit=0 should use the default (50), so we should get a non-empty next token.
	page, next, err := store.ListByTool(ctx, toolID, 0, "")
	if err != nil {
		t.Fatalf("ListByTool: %v", err)
	}
	if len(page) != 50 {
		t.Errorf("expected default page size 50, got %d", len(page))
	}
	if next == "" {
		t.Error("expected non-empty next page token for 55 results with default limit 50")
	}
}
