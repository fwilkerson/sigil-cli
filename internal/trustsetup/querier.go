package trustsetup

import (
	sigilgrpc "github.com/fwilkerson/sigil-cli/sigil/grpc"
	localtrust "github.com/fwilkerson/sigil-cli/sigil/local/trust"
)

// TrustClient returns a [localtrust.Client] backed by the gRPC connection.
func (s *TrustSetup) TrustClient() *localtrust.Client {
	return localtrust.NewClient(sigilgrpc.NewQuerier(s.Conn))
}
