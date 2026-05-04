package controlplane

import (
	"context"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// peerCNKey is the context key for the mTLS client common name.
type peerCNKey struct{}

// PeerCNFromContext extracts the mTLS client CN stored by MTLSInterceptor.
func PeerCNFromContext(ctx context.Context) (string, bool) {
	cn, ok := ctx.Value(peerCNKey{}).(string)
	return cn, ok
}

// unauthenticatedMethods lists gRPC methods that do not require mTLS peer
// verification (e.g. health checks). All other RPCs are rejected unless a
// verified client certificate is present.
var unauthenticatedMethods = map[string]bool{
	"/grpc.health.v1.Health/Check": true,
	"/grpc.health.v1.Health/Watch": true,
}

// MTLSInterceptor verifies that a TLS client certificate is present on every
// RPC (except health checks) and stores the peer CN in the context.
func MTLSInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if unauthenticatedMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Reflection endpoints are blocked unless explicitly enabled via
		// ROOTSEAL_DEBUG; the reflection service is only registered when
		// that env var is set.  If someone still manages to reach a
		// reflection method we reject it here as well.
		if strings.HasPrefix(info.FullMethod, "/grpc.reflection.") {
			return nil, status.Errorf(codes.PermissionDenied, "reflection disabled")
		}

		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "no peer info")
		}

		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing TLS credentials")
		}

		if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
			return nil, status.Errorf(codes.Unauthenticated, "no verified client certificate")
		}

		cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
		slog.Debug("mTLS peer authenticated", "cn", cn, "method", info.FullMethod)

		ctx = context.WithValue(ctx, peerCNKey{}, cn)
		return handler(ctx, req)
	}
}

// LoggingInterceptor logs gRPC requests with structured logging
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		slog.Info("grpc request",
			"method", info.FullMethod,
			"duration_ms", duration.Milliseconds(),
			"code", code.String(),
		)

		return resp, err
	}
}

// RecoveryInterceptor recovers from panics and returns an internal error
func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("panic recovered",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}
