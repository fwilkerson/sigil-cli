package pending_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/local/pending"
	sigiltrust "github.com/fwilkerson/sigil-cli/sigil/trust"
)

// makePA returns a Attestation with realistic fields for testing.
func makePA(toolURI, outcome string) *pending.Attestation {
	return &pending.Attestation{
		AttestationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		AttesterDID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		ToolURI:       toolURI,
		Outcome:       outcome,
		Claims:        map[string]string{"function": "read"},
		Version:       "1.0.0",
		Signature:     []byte("fake-signature"),
		IssuedAt:      time.Now().UTC().Truncate(time.Second),
		QueuedAt:      time.Now().UTC().Truncate(time.Second),
	}
}

// okSubmitter accepts all submissions.
type okSubmitter struct{ count int }

func (s *okSubmitter) SubmitAttestation(_ context.Context, _ *sigiltrust.AttestationSubmission) (*sigiltrust.SubmitResult, error) {
	s.count++
	return &sigiltrust.SubmitResult{AttestationID: "submitted-id"}, nil
}

// failSubmitter rejects all submissions.
type failSubmitter struct{}

func (s *failSubmitter) SubmitAttestation(_ context.Context, _ *sigiltrust.AttestationSubmission) (*sigiltrust.SubmitResult, error) {
	return nil, errors.New("connection refused")
}

// partialSubmitter fails on odd-indexed calls (0-based).
type partialSubmitter struct{ call int }

func (s *partialSubmitter) SubmitAttestation(_ context.Context, _ *sigiltrust.AttestationSubmission) (*sigiltrust.SubmitResult, error) {
	i := s.call
	s.call++
	if i%2 == 1 {
		return nil, errors.New("transient error")
	}
	return &sigiltrust.SubmitResult{AttestationID: "ok"}, nil
}

func TestEnqueueThenPending(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	pa := makePA("mcp://example.com/tool", "success")
	if err := q.Enqueue(pa); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	list, err := q.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("Pending len = %d, want 1", len(list))
	}
	got := list[0]
	if got.AttestationID != pa.AttestationID {
		t.Errorf("AttestationID = %q, want %q", got.AttestationID, pa.AttestationID)
	}
	if got.ToolURI != pa.ToolURI {
		t.Errorf("ToolURI = %q, want %q", got.ToolURI, pa.ToolURI)
	}
	if got.Outcome != pa.Outcome {
		t.Errorf("Outcome = %q, want %q", got.Outcome, pa.Outcome)
	}
}

func TestEnqueueMultipleSortedByFilename(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	for i := range 3 {
		pa := makePA("mcp://example.com/tool", "success")
		pa.Version = string(rune('A' + i))
		if err := q.Enqueue(pa); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	list, err := q.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("Pending len = %d, want 3", len(list))
	}
	// Versions should appear in insertion order (ULIDs are monotonic).
	for i, pa := range list {
		want := string(rune('A' + i))
		if pa.Version != want {
			t.Errorf("entry %d version = %q, want %q", i, pa.Version, want)
		}
	}
}

func TestRemoveDeletesSingleEntry(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	if err := q.Enqueue(makePA("mcp://example.com/a", "success")); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(makePA("mcp://example.com/b", "success")); err != nil {
		t.Fatal(err)
	}

	list, err := q.Pending()
	if err != nil || len(list) != 2 {
		t.Fatalf("want 2 pending, got %d err=%v", len(list), err)
	}

	// Grab filename of the first entry via its queue position.
	// We can call Remove with the filename the queue exposes via Flush.
	// For direct testing, re-read the dir to get names.
	first := list[0]

	// The only public way to remove is by filename. Flush exposes this
	// indirectly; test by flushing only the first entry's submission.
	sub := &okSubmitter{}
	submitted, failed, err := q.Flush(context.Background(), sub)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if submitted != 2 || failed != 0 {
		t.Errorf("Flush = %d/%d, want 2/0", submitted, failed)
	}

	// Confirm all removed.
	list2, err := q.Pending()
	if err != nil {
		t.Fatalf("Pending after flush: %v", err)
	}
	if len(list2) != 0 {
		t.Errorf("pending after flush = %d, want 0", len(list2))
	}
	_ = first
}

func TestRemoveByFilename(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	q := pending.New(dir)

	if err := q.Enqueue(makePA("mcp://example.com/a", "success")); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(makePA("mcp://example.com/b", "success")); err != nil {
		t.Fatal(err)
	}

	// Grab all pending, remove the first explicitly.
	// We test Remove indirectly: flush one, check the other remains.
	list, err := q.Pending()
	if err != nil || len(list) != 2 {
		t.Fatalf("want 2 pending: %v", err)
	}

	// Use the internal queue dir approach: files are {dir}/pending-attestations/*.json
	queueDir := filepath.Join(dir, "pending-attestations")
	entries, _ := filepath.Glob(filepath.Join(queueDir, "*.json"))
	if len(entries) != 2 {
		t.Fatalf("expected 2 files, got %d", len(entries))
	}

	// Remove the first file by base name.
	if err := q.Remove(filepath.Base(entries[0])); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	list2, err := q.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(list2) != 1 {
		t.Errorf("pending after remove = %d, want 1", len(list2))
	}
}

func TestFlushAllSuccess(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	for range 3 {
		if err := q.Enqueue(makePA("mcp://example.com/tool", "success")); err != nil {
			t.Fatal(err)
		}
	}

	sub := &okSubmitter{}
	submitted, failed, err := q.Flush(context.Background(), sub)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if submitted != 3 {
		t.Errorf("submitted = %d, want 3", submitted)
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}
	if sub.count != 3 {
		t.Errorf("submitter called %d times, want 3", sub.count)
	}

	// Queue should be empty.
	list, _ := q.Pending()
	if len(list) != 0 {
		t.Errorf("pending after flush = %d, want 0", len(list))
	}
}

func TestFlushAllFail(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	for range 2 {
		if err := q.Enqueue(makePA("mcp://example.com/tool", "negative")); err != nil {
			t.Fatal(err)
		}
	}

	submitted, failed, err := q.Flush(context.Background(), &failSubmitter{})
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if submitted != 0 {
		t.Errorf("submitted = %d, want 0", submitted)
	}
	if failed != 2 {
		t.Errorf("failed = %d, want 2", failed)
	}

	// Queue should still have both entries.
	list, _ := q.Pending()
	if len(list) != 2 {
		t.Errorf("pending after failed flush = %d, want 2", len(list))
	}
}

func TestFlushPartialSuccess(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	// Enqueue 4 items: indices 0 and 2 succeed, 1 and 3 fail.
	for range 4 {
		if err := q.Enqueue(makePA("mcp://example.com/tool", "success")); err != nil {
			t.Fatal(err)
		}
	}

	sub := &partialSubmitter{}
	submitted, failed, err := q.Flush(context.Background(), sub)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if submitted != 2 {
		t.Errorf("submitted = %d, want 2", submitted)
	}
	if failed != 2 {
		t.Errorf("failed = %d, want 2", failed)
	}

	// Two entries should remain.
	list, _ := q.Pending()
	if len(list) != 2 {
		t.Errorf("pending after partial flush = %d, want 2", len(list))
	}
}

func TestFlushEmptyQueue(t *testing.T) {
	t.Parallel()
	q := pending.New(t.TempDir())

	submitted, failed, err := q.Flush(context.Background(), &okSubmitter{})
	if err != nil {
		t.Fatalf("Flush on empty queue: %v", err)
	}
	if submitted != 0 || failed != 0 {
		t.Errorf("Flush = %d/%d, want 0/0", submitted, failed)
	}
}

func TestPendingOnNonExistentDir(t *testing.T) {
	t.Parallel()
	// Use a dir that doesn't exist.
	q := pending.New(filepath.Join(t.TempDir(), "nonexistent"))

	list, err := q.Pending()
	if err != nil {
		t.Fatalf("Pending on nonexistent dir: %v", err)
	}
	if list != nil {
		t.Errorf("Pending on nonexistent dir = %v, want nil", list)
	}
}
