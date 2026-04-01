package grpc

import (
	"context"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	trustpb "github.com/fwilkerson/sigil-cli/api/trust/v1"
	"github.com/fwilkerson/sigil-cli/sigil/trustclient"
)

// Querier implements [trustclient.TrustQuerier] via gRPC.
type Querier struct {
	client trustpb.TrustServiceClient
}

// NewQuerier returns a [trustclient.TrustQuerier] backed by conn.
func NewQuerier(conn *googlegrpc.ClientConn) *Querier {
	return &Querier{client: trustpb.NewTrustServiceClient(conn)}
}

// GetToolTrust implements [trustclient.TrustQuerier].
func (q *Querier) GetToolTrust(ctx context.Context, toolURI string) (*trustclient.ToolTrustResult, error) {
	resp, err := q.client.GetToolTrust(ctx, &trustpb.GetToolTrustRequest{
		ToolUri: toolURI,
	})
	if err != nil {
		return nil, err
	}

	result := &trustclient.ToolTrustResult{
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

// SubmitAttestation implements [trustclient.TrustQuerier].
func (q *Querier) SubmitAttestation(ctx context.Context, req *trustclient.AttestationSubmission) (*trustclient.SubmitResult, error) {
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
	return &trustclient.SubmitResult{
		AttestationID: resp.AttestationId,
		Deduplicated:  resp.Deduplicated,
	}, nil
}

// RetractAttestation implements [trustclient.TrustQuerier].
func (q *Querier) RetractAttestation(ctx context.Context, attestationID, attesterDID string, signature []byte) error {
	_, err := q.client.RetractAttestation(ctx, &trustpb.RetractAttestationRequest{
		AttestationId: attestationID,
		AttesterDid:   attesterDID,
		Signature:     signature,
	})
	return err
}

// Compile-time check.
var _ trustclient.TrustQuerier = (*Querier)(nil)
