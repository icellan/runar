package runar

import (
	"strings"
	"testing"
)

// R-051: an unrecognised or empty network string must never silently select
// mainnet. Assertions are on the RESOLVED ENDPOINT, not on an internal flag,
// so the guarantee is "these bytes never leave for a live mainnet host".

// badNetworks are the values a caller can plausibly pass by mistake: an
// unvalidated empty config value, a typo, or a wrong-case spelling.
var badNetworks = []string{"", " ", "mainnett", "MAINNET", "Mainnet", "testnett", "regtest", "main"}

func TestWhatsOnChainProvider_BadNetworkNeverResolvesMainnet(t *testing.T) {
	for _, network := range badNetworks {
		p, err := NewWhatsOnChainProvider(network)
		if err != nil {
			if p != nil {
				t.Errorf("network %q: rejected with %v but still returned a provider", network, err)
			}
			continue // rejected — acceptable
		}
		if strings.Contains(p.baseURL, "/bsv/main") {
			t.Errorf("network %q resolved to a MAINNET endpoint %q (fail-open)", network, p.baseURL)
		}
	}
}

func TestGorillaPoolProvider_BadNetworkNeverResolvesMainnet(t *testing.T) {
	for _, network := range badNetworks {
		p, err := NewGorillaPoolProvider(network)
		if err != nil {
			if p != nil {
				t.Errorf("network %q: rejected with %v but still returned a provider", network, err)
			}
			continue // rejected — acceptable
		}
		if strings.HasPrefix(p.baseURL, "https://ordinals.gorillapool.io") {
			t.Errorf("network %q resolved to a MAINNET endpoint %q (fail-open)", network, p.baseURL)
		}
	}
}

// Control: the fix must not be satisfiable by disabling mainnet entirely.
func TestProviders_ExplicitMainnetStillResolvesMainnet(t *testing.T) {
	woc, err := NewWhatsOnChainProvider("mainnet")
	if err != nil || woc.baseURL != "https://api.whatsonchain.com/v1/bsv/main" {
		t.Errorf("explicit mainnet WoC endpoint: got %v, err %v", woc, err)
	}
	gp, err := NewGorillaPoolProvider("mainnet")
	if err != nil || gp.baseURL != "https://ordinals.gorillapool.io/api" {
		t.Errorf("explicit mainnet GorillaPool endpoint: got %v, err %v", gp, err)
	}
	wocT, err := NewWhatsOnChainProvider("testnet")
	if err != nil || wocT.baseURL != "https://api.whatsonchain.com/v1/bsv/test" {
		t.Errorf("explicit testnet WoC endpoint: got %v, err %v", wocT, err)
	}
	gpT, err := NewGorillaPoolProvider("testnet")
	if err != nil || gpT.baseURL != "https://testnet.ordinals.gorillapool.io/api" {
		t.Errorf("explicit testnet GorillaPool endpoint: got %v, err %v", gpT, err)
	}
}

// The rejection message must name the offending value and the accepted set.
func TestProviders_RejectionErrorIsActionable(t *testing.T) {
	if _, err := NewWhatsOnChainProvider("mainnett"); err == nil {
		t.Fatal("WoC: expected an error for \"mainnett\"")
	} else if !strings.Contains(err.Error(), "mainnett") || !strings.Contains(err.Error(), "testnet") {
		t.Errorf("WoC error not actionable: %v", err)
	}
	if _, err := NewGorillaPoolProvider(""); err == nil {
		t.Fatal("GorillaPool: expected an error for the empty string")
	} else if !strings.Contains(err.Error(), "testnet") {
		t.Errorf("GorillaPool error not actionable: %v", err)
	}
}
