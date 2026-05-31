package controlplane

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"rootseal/pkg/api"
)

// enrollmentTokenMDKey is the gRPC metadata header carrying the single-use
// enrollment token. It is passed out-of-band (not in the proto body) so it is
// never persisted with the request and is easy to redact from logs.
const enrollmentTokenMDKey = "x-rootseal-enrollment-token" // #nosec G101 -- metadata header name, not a credential

// auditAllow emits a structured audit log for an allowed security decision.
// Sensitive material (keys, tokens, quotes) is never included.
func auditAllow(event, volumeUUID, cn string) {
	slog.Info("audit", "event", event, "decision", "allow", "volume_uuid", volumeUUID, "peer_cn", cn)
}

// auditDeny emits a structured audit log for a denied security decision. The
// reason is recorded server-side only; clients receive a generic error.
func auditDeny(event, volumeUUID, cn, reason string) {
	slog.Warn("audit", "event", event, "decision", "deny", "volume_uuid", volumeUUID, "peer_cn", cn, "reason", reason)
}

// authorizeVolume enforces that the authenticated mTLS client identity is the
// one bound to the volume's agent at enrollment time. It fails closed: a
// missing identity, a lookup failure, a revoked host, or any mismatch results
// in PermissionDenied. Detailed reasons are logged server-side; the client
// only learns that access was denied.
//
// When requireAuth is false (explicit insecure dev mode with no mTLS) the check
// is skipped — this combination is opt-in and loudly warned about at startup.
func (s *server) authorizeVolume(ctx context.Context, event string, volume *Volume) error {
	if !s.requireAuth {
		return nil
	}

	cn, ok := PeerCNFromContext(ctx)
	if !ok || cn == "" {
		auditDeny(event, volume.UUID, "", "no authenticated client identity")
		return status.Error(codes.PermissionDenied, "not authorized")
	}

	agent, err := s.db.GetAgent(ctx, volume.AgentID)
	if err != nil {
		auditDeny(event, volume.UUID, cn, "agent lookup failed")
		return status.Error(codes.PermissionDenied, "not authorized")
	}

	if agent.Revoked {
		auditDeny(event, volume.UUID, cn, "host revoked")
		return status.Error(codes.PermissionDenied, "not authorized")
	}

	if agent.AuthorizedCN == "" {
		auditDeny(event, volume.UUID, cn, "volume has no authorized identity")
		return status.Error(codes.PermissionDenied, "not authorized")
	}

	if subtle.ConstantTimeCompare([]byte(agent.AuthorizedCN), []byte(cn)) != 1 {
		auditDeny(event, volume.UUID, cn, "client identity not authorized for volume")
		return status.Error(codes.PermissionDenied, "not authorized")
	}

	return nil
}

// enrollmentTokenFromContext returns the enrollment token supplied via gRPC
// metadata, if any.
func enrollmentTokenFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(enrollmentTokenMDKey)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// pcrsToPinned serializes the PCR values from a quote into a stable JSON map of
// PCR index -> lowercase hex digest, suitable for storage and comparison.
func pcrsToPinned(pcrs []*api.PCRValue) ([]byte, error) {
	m := make(map[string]string, len(pcrs))
	for _, p := range pcrs {
		m[fmt.Sprintf("%d", p.GetIndex())] = hex.EncodeToString(p.GetDigest())
	}
	return json.Marshal(m)
}

// pcrsMatchPinned reports whether the PCR values in a quote exactly match the
// previously pinned digests. Every pinned PCR must be present in the quote with
// an identical digest.
func pcrsMatchPinned(pinned []byte, pcrs []*api.PCRValue) (bool, error) {
	var want map[string]string
	if err := json.Unmarshal(pinned, &want); err != nil {
		return false, err
	}
	got := make(map[string]string, len(pcrs))
	for _, p := range pcrs {
		got[fmt.Sprintf("%d", p.GetIndex())] = hex.EncodeToString(p.GetDigest())
	}

	// Compare deterministically over the sorted pinned indices.
	idxs := make([]string, 0, len(want))
	for k := range want {
		idxs = append(idxs, k)
	}
	sort.Strings(idxs)
	for _, idx := range idxs {
		if subtle.ConstantTimeCompare([]byte(want[idx]), []byte(got[idx])) != 1 {
			return false, nil
		}
	}
	return true, nil
}
