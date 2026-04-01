package trustsetup

import (
	"fmt"

	"google.golang.org/grpc"

	sigilgrpc "github.com/fwilkerson/sigil-cli/sigil/grpc"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
)

// TrustSetup holds the identity, gRPC connection, and config for trust commands.
type TrustSetup struct {
	KeyPair *signing.KeyPair
	DID     identity.DID
	Config  *Config
	Conn    *grpc.ClientConn
}

// Connect dials the trust service and returns a setup with the connection.
func Connect(addr string) (*TrustSetup, error) {
	conn, err := grpc.NewClient(addr, sigilgrpc.DialOpts()...)
	if err != nil {
		return nil, fmt.Errorf("connect to trust service: %w", err)
	}
	return &TrustSetup{Conn: conn}, nil
}

// Close releases the gRPC connection.
func (s *TrustSetup) Close() error {
	if s.Conn != nil {
		return s.Conn.Close()
	}
	return nil
}
