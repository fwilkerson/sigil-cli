package trustsetup

import (
	sigilgrpc "github.com/fwilkerson/sigil-cli/sigil/grpc"
	"github.com/fwilkerson/sigil-cli/sigil/trustclient"
)

// TrustClient returns a [trustclient.Client] backed by the gRPC connection.
func (s *TrustSetup) TrustClient() *trustclient.Client {
	return trustclient.NewClient(sigilgrpc.NewQuerier(s.Conn))
}
