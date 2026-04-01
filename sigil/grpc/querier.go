package grpc

import (
	"context"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	trustpb "github.com/fwilkerson/sigil-cli/api/trust/v1"
	sigiltrust "github.com/fwilkerson/sigil-cli/sigil/trust"
)

// Querier implements [sigiltrust.Querier] via gRPC.
type Querier struct {
	client trustpb.TrustServiceClient
}

// NewQuerier returns a [sigiltrust.Querier] backed by conn.
func NewQuerier(conn *googlegrpc.ClientConn) *Querier {
	return &Querier{client: trustpb.NewTrustServiceClient(conn)}
}

// GetToolTrust implements [sigiltrust.Querier].
func (q *Querier) GetToolTrust(ctx context.Context, toolURI string) (*sigiltrust.ToolTrustResult, error) {
	resp, err := q.client.GetToolTrust(ctx, &trustpb.GetToolTrustRequest{
		ToolUri: toolURI,
	})
	if err != nil {
		return nil, err
	}

	result := &sigiltrust.ToolTrustResult{
		Score:             resp.Score,
		TotalAttestations: int(resp.TotalAttestations),
		UniqueAttesters:   int(resp.UniqueAttesters),
		SuccessRate:       resp.SuccessRate,
		Provisional:       resp.Provisional,
		VersionsAttested:  int(resp.VersionsAttested),
		LatestVersion:     resp.LatestVersion,
	}
	if resp.FirstSeen != nil {
		result.FirstSeen = resp.FirstSeen.AsTime()
	}
	if resp.LastActive != nil {
		result.LastActive = resp.LastActive.AsTime()
	}
	return result, nil
}

// SubmitAttestation implements [sigiltrust.Querier].
func (q *Querier) SubmitAttestation(ctx context.Context, req *sigiltrust.AttestationSubmission) (*sigiltrust.SubmitResult, error) {
	resp, err := q.client.SubmitAttestation(ctx, &trustpb.SubmitAttestationRequest{
		AttestationId: req.AttestationID,
		AttesterDid:   req.AttesterDID,
		ToolUri:       req.ToolURI,
		Outcome:       req.Outcome,
		Claims:        req.Claims,
		Version:       req.Version,
		Signature:     req.Signature,
		IssuedAt:      timestamppb.New(req.IssuedAt),
	})
	if err != nil {
		return nil, err
	}
	return &sigiltrust.SubmitResult{
		AttestationID: resp.AttestationId,
		Deduplicated:  resp.Deduplicated,
	}, nil
}

// RetractAttestation implements [sigiltrust.Querier].
func (q *Querier) RetractAttestation(ctx context.Context, attestationID, attesterDID string, signature []byte) error {
	_, err := q.client.RetractAttestation(ctx, &trustpb.RetractAttestationRequest{
		AttestationId: attestationID,
		AttesterDid:   attesterDID,
		Signature:     signature,
	})
	return err
}

// Compile-time check.
var _ sigiltrust.Querier = (*Querier)(nil)
