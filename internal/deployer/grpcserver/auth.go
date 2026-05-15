package grpcserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// tokenLabel is the HKDF info string for the deployer RPC bearer token.
// Distinct from agentctrl's command-signing label so the same encryption
// key produces different secrets for each surface — leaking one does
// not compromise the other.
const tokenLabel = "muvon-deployer-rpc-v1"

// AuthMetadataKey is the gRPC metadata key the client puts the bearer
// token under. Lowercase per gRPC convention.
const AuthMetadataKey = "x-muvon-deployer-token"

// DeriveDeployerToken returns the hex-encoded bearer token derived
// from MUVON_ENCRYPTION_KEY. Central admin (client) and agent
// (server) both compute it on startup; an empty passphrase short-
// circuits the wiring (caller should refuse to bind the TCP listener).
func DeriveDeployerToken(passphrase string) (string, error) {
	if passphrase == "" {
		return "", errors.New("deployer rpc: MUVON_ENCRYPTION_KEY required to derive token")
	}
	ikm := sha256.Sum256([]byte(passphrase))
	r := hkdf.New(sha256.New, ikm[:], nil, []byte(tokenLabel))
	out := make([]byte, 32)
	if _, err := r.Read(out); err != nil {
		return "", fmt.Errorf("hkdf: %w", err)
	}
	return hex.EncodeToString(out), nil
}

// UnaryAuthInterceptor verifies the bearer token on unary RPCs. Returns
// Unauthenticated when missing/mismatched. The token byte slice is the
// expected hex string (raw bytes); we compare in constant time on the
// metadata value to defeat timing oracles.
func UnaryAuthInterceptor(token string) grpc.UnaryServerInterceptor {
	expected := []byte(token)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := verifyToken(ctx, expected); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamAuthInterceptor is the streaming counterpart.
func StreamAuthInterceptor(token string) grpc.StreamServerInterceptor {
	expected := []byte(token)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := verifyToken(ss.Context(), expected); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func verifyToken(ctx context.Context, expected []byte) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	vals := md.Get(AuthMetadataKey)
	if len(vals) == 0 {
		return status.Error(codes.Unauthenticated, "missing deployer token")
	}
	got := []byte(vals[0])
	if !hmac.Equal(got, expected) {
		return status.Error(codes.Unauthenticated, "invalid deployer token")
	}
	return nil
}
