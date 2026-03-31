// Package pending implements a file-based queue for attestations that could
// not be submitted to the trust service (e.g. because it was unreachable).
// Attestations are stored as JSON files in {configDir}/pending-attestations/
// and are flushed on the next successful connection.
package pending

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/fwilkerson/sigil-cli/proto/trustclient"
)

// PendingAttestation holds a signed attestation that could not be submitted.
// All fields needed to reconstruct and submit the AttestationSubmission are
// stored here together with housekeeping timestamps.
type PendingAttestation struct {
	AttestationID string            `json:"attestation_id"`
	AttesterDID   string            `json:"attester_did"`
	ToolURI       string            `json:"tool_uri"`
	Outcome       string            `json:"outcome"`
	Claims        map[string]string `json:"claims,omitempty"`
	Version       string            `json:"version,omitempty"`
	Signature     []byte            `json:"signature"`
	IssuedAt      time.Time         `json:"issued_at"`
	QueuedAt      time.Time         `json:"queued_at"`

	// queueFilename is the base filename of the queue file. It is populated by
	// Pending() and used by Flush(); it is not persisted to disk.
	queueFilename string
}

// Submitter can submit a signed attestation to the trust service.
type Submitter interface {
	SubmitAttestation(ctx context.Context, req *trustclient.AttestationSubmission) (*trustclient.SubmitResult, error)
}

// Queue is a file-based queue of pending attestations.
type Queue struct {
	dir string
}

// New returns a Queue rooted at {configDir}/pending-attestations/.
func New(configDir string) *Queue {
	return &Queue{dir: filepath.Join(configDir, "pending-attestations")}
}

// Enqueue persists pa as a JSON file in the queue directory. The directory is
// created lazily on the first call.
func (q *Queue) Enqueue(pa *PendingAttestation) error {
	if err := os.MkdirAll(q.dir, 0o700); err != nil {
		return fmt.Errorf("create pending-attestations dir: %w", err)
	}

	name := ulid.Make().String() + ".json"
	path := filepath.Join(q.dir, name)

	data, err := json.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal pending attestation: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write pending attestation %s: %w", name, err)
	}
	return nil
}

// Pending returns all queued attestations, sorted by filename (ULID order =
// creation order). Returns nil, nil when the queue directory does not exist.
func (q *Queue) Pending() ([]*PendingAttestation, error) {
	entries, err := os.ReadDir(q.dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pending-attestations dir: %w", err)
	}

	// Collect .json filenames and sort (ReadDir already returns sorted, but
	// sort explicitly to make the contract clear).
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	out := make([]*PendingAttestation, 0, len(names))
	for _, name := range names {
		pa, err := q.load(name)
		if err != nil {
			// Skip malformed files rather than aborting the whole flush.
			continue
		}
		pa.queueFilename = name
		out = append(out, pa)
	}
	return out, nil
}

// Remove deletes a single queue entry by its base filename (e.g.
// "01ARZ3NDEKTSV4RRFFQ69G5FAV.json").
func (q *Queue) Remove(filename string) error {
	path := filepath.Join(q.dir, filepath.Base(filename))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove pending attestation %s: %w", filename, err)
	}
	return nil
}

// Flush submits all pending attestations using sub. Successful submissions are
// removed from the queue; failures are counted but do not abort the flush.
// Returns the number of successfully submitted and failed attestations.
func (q *Queue) Flush(ctx context.Context, sub Submitter) (submitted, failed int, err error) {
	pending, err := q.Pending()
	if err != nil {
		return 0, 0, err
	}

	for _, pa := range pending {
		req := &trustclient.AttestationSubmission{
			AttestationID: pa.AttestationID,
			AttesterDID:   pa.AttesterDID,
			ToolURI:       pa.ToolURI,
			Outcome:       pa.Outcome,
			Claims:        pa.Claims,
			Version:       pa.Version,
			Signature:     pa.Signature,
			IssuedAt:      pa.IssuedAt,
		}
		if _, subErr := sub.SubmitAttestation(ctx, req); subErr != nil {
			failed++
			continue
		}
		if removeErr := q.Remove(pa.queueFilename); removeErr != nil {
			// Count as failed if we can't clean up; we'll retry on next flush.
			failed++
			continue
		}
		submitted++
	}
	return submitted, failed, nil
}

// load reads and unmarshals a single queue file.
func (q *Queue) load(name string) (*PendingAttestation, error) {
	path := filepath.Join(q.dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > 1<<20 { // 1 MB
		return nil, fmt.Errorf("pending attestation %s too large (%d bytes)", name, fi.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pa PendingAttestation
	if err := json.Unmarshal(data, &pa); err != nil {
		return nil, err
	}
	return &pa, nil
}
