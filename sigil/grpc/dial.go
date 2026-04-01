// Package grpc provides gRPC transport adapters for the Sigil trust service.
package grpc

import (
	"crypto/tls"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DialOpts returns the default gRPC dial options for connecting to the trust service.
func DialOpts() []googlegrpc.DialOption {
	return []googlegrpc.DialOption{
		googlegrpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
	}
}
