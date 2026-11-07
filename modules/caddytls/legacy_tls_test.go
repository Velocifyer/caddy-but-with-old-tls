// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"crypto/tls"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestLegacyTLSConnectionPolicy(t *testing.T) {
	policy := &ConnectionPolicy{
		ProtocolMin: "tls1.1",
		ProtocolMax: "tls1.3",
		CipherSuites: []string{
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		},
	}

	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := (ConnectionPolicies{policy}).Provision(ctx); err != nil {
		t.Fatalf("provisioning legacy TLS connection policy: %v", err)
	}

	if got := policy.TLSConfig.MinVersion; got != tls.VersionTLS11 {
		t.Errorf("MinVersion = %x, want TLS 1.1 (%x)", got, tls.VersionTLS11)
	}
	if got := policy.TLSConfig.MaxVersion; got != tls.VersionTLS13 {
		t.Errorf("MaxVersion = %x, want TLS 1.3 (%x)", got, tls.VersionTLS13)
	}

	wantCipherSuites := []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	for i, want := range wantCipherSuites {
		if got := policy.TLSConfig.CipherSuites[i+1]; got != want {
			// The first entry is Caddy's TLS_FALLBACK_SCSV, which is added
			// after the policy's configured cipher suites.
			t.Errorf("CipherSuites[%d] = %x, want %x", i+1, got, want)
		}
	}
}

func TestLegacyTLSValuesAreOptIn(t *testing.T) {
	if got := SupportedProtocols["tls1.1"]; got != tls.VersionTLS11 {
		t.Errorf("SupportedProtocols[tls1.1] = %x, want %x", got, tls.VersionTLS11)
	}
	for _, name := range []string{
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	} {
		if CipherSuiteID(name) == 0 {
			t.Errorf("CipherSuiteID(%q) = 0, want a supported cipher suite ID", name)
		}
	}

	// The legacy suites are accepted when explicitly selected, but stay out
	// of Caddy's defaults so ordinary sites retain their secure configuration.
	for _, id := range getOptimalDefaultCipherSuites() {
		if id == tls.TLS_RSA_WITH_AES_128_CBC_SHA || id == tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA {
			t.Errorf("legacy cipher suite %x unexpectedly appears in defaults", id)
		}
	}
}
