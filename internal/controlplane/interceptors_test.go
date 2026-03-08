package controlplane

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var fakeInfo = &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

func TestRecoveryInterceptor_Normal(t *testing.T) {
	want := "result"
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return want, nil
	}

	resp, err := RecoveryInterceptor()(context.Background(), nil, fakeInfo, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != want {
		t.Errorf("response: got %v want %v", resp, want)
	}
}

func TestRecoveryInterceptor_Panic(t *testing.T) {
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic("something went wrong")
	}

	_, err := RecoveryInterceptor()(context.Background(), nil, fakeInfo, handler)
	if err == nil {
		t.Fatal("expected error after panic, got nil")
	}
	if code := status.Code(err); code != codes.Internal {
		t.Errorf("gRPC code: got %v want %v", code, codes.Internal)
	}
}

func TestRecoveryInterceptor_HandlerError(t *testing.T) {
	want := errors.New("handler error")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, want
	}

	_, err := RecoveryInterceptor()(context.Background(), nil, fakeInfo, handler)
	if !errors.Is(err, want) {
		t.Errorf("error: got %v want %v", err, want)
	}
}

func TestLoggingInterceptor_PassThrough(t *testing.T) {
	want := "logged-result"
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return want, nil
	}

	resp, err := LoggingInterceptor()(context.Background(), nil, fakeInfo, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != want {
		t.Errorf("response: got %v want %v", resp, want)
	}
}

func TestLoggingInterceptor_PropagatesError(t *testing.T) {
	want := status.Errorf(codes.NotFound, "not found")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, want
	}

	_, err := LoggingInterceptor()(context.Background(), nil, fakeInfo, handler)
	if status.Code(err) != codes.NotFound {
		t.Errorf("error code: got %v want NotFound", status.Code(err))
	}
}
