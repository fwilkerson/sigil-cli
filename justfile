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
