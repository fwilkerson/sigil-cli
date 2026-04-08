# Generate Go protobuf and gRPC client stubs (server stubs stripped).
proto:
    protoc \
        --proto_path=. \
        --go_out=paths=source_relative:. \
        --go-grpc_out=paths=source_relative:. \
        api/trust/v1/trust.proto
    @# protoc-gen-go-grpc v1.6.x has no gen-server=false flag, so strip
    @# server stubs (interfaces, handlers, ServiceDesc) after generation.
    sed -i.bak '/^\/\/ TrustServiceServer is the server API/,$d' \
        api/trust/v1/trust_grpc.pb.go
    rm -f api/trust/v1/trust_grpc.pb.go.bak
    goimports -w api/trust/v1/trust_grpc.pb.go

# Cross-compile release binaries and generate checksums.
build-all version="0.0.0" commit=`git rev-parse --short HEAD` trust_addr="sigil-trust.dev:443":
	#!/usr/bin/env bash
	set -euo pipefail
	ldflags="-X github.com/fwilkerson/sigil-cli/cmd/buildinfo.Version={{version}} -X github.com/fwilkerson/sigil-cli/cmd/buildinfo.Commit={{commit}} -X github.com/fwilkerson/sigil-cli/cmd/buildinfo.TrustAddr={{trust_addr}}"
	for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
		os="${target%/*}"
		arch="${target#*/}"
		CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -tags release -ldflags "$ldflags" -o "dist/sigil-${os}-${arch}" .
	done
	cd dist && shasum -a 256 sigil-* > checksums.txt
