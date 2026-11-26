package authconfig

import (
	"fmt"
	"net/url"
	"strings"
)

// central.go defines the opt-in deployment boundary for shared authentication.
// These values are startup configuration, separate from mutable generic OIDC
// settings. A deployment chooses its authority continuity, exact browser origin,
// confidential human client and separate workload client before any account can
// become central-managed. Existing installations retain current authentication
// paths when this switch is absent.
//
// Production endpoints require HTTPS and canonical URLs without credentials,
// fragments or query overrides. A separately named TEST loopback profile permits
// local native integration fixtures; it cannot admit remote HTTP endpoints.
// Legacy migration has an additional default-off TEST profile and no production
// alias. Qualifying a recovery policy requires a deliberate configuration and
// contract change instead of interpreting a boolean as independent proof.

// CentralIdentityConfig holds deployment-pinned central authentication inputs.
type CentralIdentityConfig struct {
	Enabled              bool     `mapstructure:"enabled"`                // explicit shared-authentication activation
	Origin               string   `mapstructure:"origin"`                 // exact browser origin without trailing slash
	APIURL               string   `mapstructure:"api_url"`                // trusted Identity Connect base URL
	IssuerURL            string   `mapstructure:"issuer_url"`             // exact Keycloak realm issuer
	AuthorityIncarnation string   `mapstructure:"authority_incarnation"`  // configured authority continuity
	ConsumerID           string   `mapstructure:"consumer_id"`            // logical consumer attachment identifier
	ClientID             string   `mapstructure:"client_id"`              // confidential browser-flow client
	ClientSecret         string   `mapstructure:"client_secret"`          // server-held browser client secret
	WorkloadClientID     string   `mapstructure:"workload_client_id"`     // distinct consumer status client
	WorkloadClientSecret string   `mapstructure:"workload_client_secret"` // server-held workload secret
	ProviderName         string   `mapstructure:"provider_name"`          // displayed shared identity service label
	Providers            []string `mapstructure:"providers"`              // allowlisted Keycloak broker aliases
	TestLoopback         bool     `mapstructure:"test_loopback"`          // local TEST HTTP and non-Secure cookie profile
	TestBindingProfile   string   `mapstructure:"test_binding_profile"`   // optional TEST migration candidate
}

// Validate rejects incomplete configuration and noncanonical transport boundaries.
// Strong organizational admission deliberately has no enablement field here.
func (c CentralIdentityConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	for name, value := range map[string]string{"authority_incarnation": c.AuthorityIncarnation, "consumer_id": c.ConsumerID, "client_id": c.ClientID, "client_secret": c.ClientSecret, "workload_client_id": c.WorkloadClientID, "workload_client_secret": c.WorkloadClientSecret} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("central_identity.%s must be a bounded nonempty value", name)
		}
	}
	if c.ClientID == c.WorkloadClientID {
		return fmt.Errorf("central_identity requires distinct browser and workload clients")
	}
	for name, value := range map[string]string{"origin": c.Origin, "api_url": c.APIURL, "issuer_url": c.IssuerURL} {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || value != strings.TrimRight(value, "/") || u.RawPath != "" || len(value) > 2048 {
			return fmt.Errorf("central_identity.%s must be a canonical absolute URL", name)
		}
		loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
		if c.TestLoopback && !loopback {
			return fmt.Errorf("central_identity.test_loopback only admits loopback endpoints")
		}
		if u.Scheme != "https" && !(c.TestLoopback && u.Scheme == "http" && loopback) {
			return fmt.Errorf("central_identity.%s requires HTTPS outside the TEST loopback profile", name)
		}
		if name == "origin" && u.Path != "" {
			return fmt.Errorf("central_identity.origin must not contain a path")
		}
	}
	if c.TestBindingProfile != "" && (!c.TestLoopback || c.TestBindingProfile != "test-password-totp-v1") {
		return fmt.Errorf("central_identity.test_binding_profile is an unqualified TEST-only migration candidate")
	}
	if len(c.Providers) > 8 {
		return fmt.Errorf("central_identity.providers exceeds the bounded broker allowlist")
	}
	seen := make(map[string]bool)
	for _, alias := range c.Providers {
		if alias == "" || len(alias) > 64 || seen[alias] {
			return fmt.Errorf("central_identity.providers contains an invalid or repeated alias")
		}
		for _, letter := range alias {
			if !(letter >= 'a' && letter <= 'z' || letter >= '0' && letter <= '9' || letter == '-' || letter == '_') {
				return fmt.Errorf("central_identity.providers contains an invalid alias")
			}
		}
		seen[alias] = true
	}
	return nil
}
