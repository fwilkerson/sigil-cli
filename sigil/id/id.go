// Package id provides typed ULID identifiers for the Sigil protocol.
//
// Each domain concept gets its own type so the compiler prevents mixing
// an ActorID where a TransactionID is expected.
package id

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// ActorID identifies a protocol participant (Patron, Runner, Merchant).
type ActorID struct{ v ulid.ULID }

// TransactionID identifies a transaction flow instance.
type TransactionID struct{ v ulid.ULID }

// SigilID identifies an attestation (sigil).
type SigilID struct{ v ulid.ULID }

// AuditID identifies an audit trail entry.
type AuditID struct{ v ulid.ULID }

// NewActorID generates a new unique ActorID.
func NewActorID() ActorID { return ActorID{v: mustNew()} }

// NewTransactionID generates a new unique TransactionID.
func NewTransactionID() TransactionID { return TransactionID{v: mustNew()} }

// NewSigilID generates a new unique SigilID.
func NewSigilID() SigilID { return SigilID{v: mustNew()} }

// NewAuditID generates a new unique AuditID.
func NewAuditID() AuditID { return AuditID{v: mustNew()} }

// String returns the ULID string representation.
func (id ActorID) String() string { return id.v.String() }

// String returns the ULID string representation.
func (id TransactionID) String() string { return id.v.String() }

// String returns the ULID string representation.
func (id SigilID) String() string { return id.v.String() }

// String returns the ULID string representation.
func (id AuditID) String() string { return id.v.String() }

// Time returns the timestamp embedded in the ULID.
func (id ActorID) Time() time.Time { return ulid.Time(id.v.Time()) }

// Time returns the timestamp embedded in the ULID.
func (id TransactionID) Time() time.Time { return ulid.Time(id.v.Time()) }

// Time returns the timestamp embedded in the ULID.
func (id SigilID) Time() time.Time { return ulid.Time(id.v.Time()) }

// Time returns the timestamp embedded in the ULID.
func (id AuditID) Time() time.Time { return ulid.Time(id.v.Time()) }

// IsZero returns true if the ID is the zero value.
func (id ActorID) IsZero() bool { return id.v == ulid.ULID{} }

// IsZero returns true if the ID is the zero value.
func (id TransactionID) IsZero() bool { return id.v == ulid.ULID{} }

// IsZero returns true if the ID is the zero value.
func (id SigilID) IsZero() bool { return id.v == ulid.ULID{} }

// IsZero returns true if the ID is the zero value.
func (id AuditID) IsZero() bool { return id.v == ulid.ULID{} }

// ParseActorID parses a ULID string into an ActorID.
func ParseActorID(s string) (ActorID, error) {
	v, err := ulid.ParseStrict(s)
	if err != nil {
		return ActorID{}, fmt.Errorf("parse ActorID: %w", err)
	}
	return ActorID{v: v}, nil
}

// ParseTransactionID parses a ULID string into a TransactionID.
func ParseTransactionID(s string) (TransactionID, error) {
	v, err := ulid.ParseStrict(s)
	if err != nil {
		return TransactionID{}, fmt.Errorf("parse TransactionID: %w", err)
	}
	return TransactionID{v: v}, nil
}

// ParseSigilID parses a ULID string into a SigilID.
func ParseSigilID(s string) (SigilID, error) {
	v, err := ulid.ParseStrict(s)
	if err != nil {
		return SigilID{}, fmt.Errorf("parse SigilID: %w", err)
	}
	return SigilID{v: v}, nil
}

// ParseAuditID parses a ULID string into an AuditID.
func ParseAuditID(s string) (AuditID, error) {
	v, err := ulid.ParseStrict(s)
	if err != nil {
		return AuditID{}, fmt.Errorf("parse AuditID: %w", err)
	}
	return AuditID{v: v}, nil
}

// MarshalText implements encoding.TextMarshaler for JSON support.
func (id ActorID) MarshalText() ([]byte, error) { return id.v.MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler for JSON support.
func (id *ActorID) UnmarshalText(data []byte) error { return id.v.UnmarshalText(data) }

// MarshalText implements encoding.TextMarshaler for JSON support.
func (id TransactionID) MarshalText() ([]byte, error) { return id.v.MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler for JSON support.
func (id *TransactionID) UnmarshalText(data []byte) error { return id.v.UnmarshalText(data) }

// MarshalText implements encoding.TextMarshaler for JSON support.
func (id SigilID) MarshalText() ([]byte, error) { return id.v.MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler for JSON support.
func (id *SigilID) UnmarshalText(data []byte) error { return id.v.UnmarshalText(data) }

// MarshalText implements encoding.TextMarshaler for JSON support.
func (id AuditID) MarshalText() ([]byte, error) { return id.v.MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler for JSON support.
func (id *AuditID) UnmarshalText(data []byte) error { return id.v.UnmarshalText(data) }

func mustNew() ulid.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}
