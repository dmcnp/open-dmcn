package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
)

// provisionIdentity is the operator-side half of self-service registration: given a verified,
// self-signed IdentityRecord for this node's domain, attach the operator routing attestation
// (RelayHints = this node, signed by the domain root) and publish it to the fleet. This is the
// same operator step as the boot seed (seedIdentity), for a browser-provided record. The daemon
// never holds the account's private key — only the signed public record.
//
// It enforces the two node-owned checks: the address must be on the served domain, and must not
// already be registered.
func provisionIdentity(ctx context.Context, n *node.Node, rootKP *identity.IdentityKeyPair, domain string, rec *identity.IdentityRecord, at time.Time) (string, error) {
	local, addrDomain, ok := strings.Cut(rec.Address, "@")
	if !ok || local == "" {
		return "", webapi.ErrRegisterInvalidAddress
	}
	if !strings.EqualFold(addrDomain, domain) {
		return "", webapi.ErrRegisterDomainNotServed
	}
	if _, err := n.Lookup(ctx, rec.Address); err == nil {
		return "", webapi.ErrRegisterExists
	}
	hints := n.RelayHints()
	if len(hints) == 0 {
		return "", fmt.Errorf("node has no relay hint to route %s", rec.Address)
	}
	if err := rec.IssueRoutingCredential(rootKP, hints, at); err != nil {
		return "", fmt.Errorf("issue routing credential: %w", err)
	}
	if _, err := n.PublishIdentity(ctx, rec); err != nil {
		return "", fmt.Errorf("publish identity: %w", err)
	}
	return "active", nil
}
