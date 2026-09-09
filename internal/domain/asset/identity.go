package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"ai-surface-platform/internal/domain/endpoint"
)

// Identity computes the deterministic natural key for a. The strategy
// depends on the asset's Type — never on a display name, and never on
// mutable observed content such as a response body:
//
//	HOST / DOMAIN / SUBDOMAIN: normalized hostname
//	IP:                        canonical IP address
//	PORT / SERVICE:            normalized host + port + protocol
//	HTTP_ENDPOINT / API_ENDPOINT / AI_ENDPOINT: scheme + normalized host +
//	                           normalized port + normalized path
//	REPOSITORY / CLOUD_RESOURCE / MODEL_ENDPOINT: type + whichever of
//	                           URL/Hostname/Technology+Model identifies it
//
// Two observations that produce the same Identity are the same asset; see
// IdentityKey for the value actually stored and compared in the database.
func Identity(a Asset) (string, error) {
	switch {
	case hostnameTypes[a.Type]:
		host := StringField(a.Hostname)
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("%s asset requires a hostname", a.Type)
		}
		return string(a.Type) + ":" + normalizeHostname(host), nil

	case a.Type == TypeIP:
		ip := StringField(a.IP)
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil {
			return "", fmt.Errorf("IP asset requires a valid IP address, got %q", ip)
		}
		return "IP:" + parsed.String(), nil

	case portTypes[a.Type]:
		host := StringField(a.Hostname)
		if host == "" {
			host = StringField(a.IP)
		}
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("%s asset requires a hostname or IP", a.Type)
		}
		if a.Port == nil {
			return "", fmt.Errorf("%s asset requires a port", a.Type)
		}
		protocol := strings.ToLower(strings.TrimSpace(StringField(a.Protocol)))
		if protocol == "" {
			protocol = "tcp"
		}
		return fmt.Sprintf("%s:%s:%d:%s", a.Type, normalizeHostname(host), *a.Port, protocol), nil

	case endpointTypes[a.Type]:
		raw := StringField(a.URL)
		if strings.TrimSpace(raw) == "" {
			return "", fmt.Errorf("%s asset requires a URL", a.Type)
		}
		norm, err := endpoint.Normalize(raw)
		if err != nil {
			return "", fmt.Errorf("normalizing asset URL: %w", err)
		}
		return string(a.Type) + ":" + norm.URL, nil

	default:
		// REPOSITORY, CLOUD_RESOURCE, MODEL_ENDPOINT and any future type
		// without a dedicated rule: fall back to the most specific
		// identifying field available, in a fixed order of preference.
		if url := strings.TrimSpace(StringField(a.URL)); url != "" {
			return string(a.Type) + ":url:" + url, nil
		}
		if host := strings.TrimSpace(StringField(a.Hostname)); host != "" {
			return string(a.Type) + ":host:" + normalizeHostname(host), nil
		}
		provider := strings.TrimSpace(StringField(a.Provider))
		model := strings.TrimSpace(StringField(a.Model))
		if provider != "" || model != "" {
			return string(a.Type) + ":model:" + provider + "/" + model, nil
		}
		return "", fmt.Errorf("%s asset requires a URL, hostname, or provider/model to compute identity", a.Type)
	}
}

// IdentityKey returns the SHA-256 hex digest of Identity(a) — the value
// actually stored in assets.identity_key and compared under the
// (target_id, identity_key) uniqueness constraint. Hashing keeps the
// stored/indexed value a fixed size regardless of how long the underlying
// identity string is (e.g. a long URL path).
func IdentityKey(a Asset) (string, error) {
	id, err := Identity(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:]), nil
}

// normalizeHostname lowercases and trims a trailing dot, so
// "Example.com." and "example.com" identify the same asset.
func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
