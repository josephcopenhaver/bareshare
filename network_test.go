package main

import (
	"context"
	"net"
	"testing"
)

// TestResolveUDPAddrPreservesIPv6Zone is a regression test for resolveUDPAddr
// dropping the interface scope of a link-local IPv6 literal. LookupNetIP is
// implemented on top of LookupIP, which discards IPAddr.Zone, so a target such
// as [fe80::1%en0]:4242 resolved through it comes back unscoped and cannot
// reach the link-local peer.
func TestResolveUDPAddrPreservesIPv6Zone(t *testing.T) {
	t.Parallel()

	const (
		wantZone = "en0"
		wantPort = 4242
	)
	wantIP := net.ParseIP("fe80::1")

	for _, network := range []string{"udp6", "udp"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()

			got, err := resolveUDPAddr(context.Background(), net.DefaultResolver, network, "[fe80::1%en0]:4242")
			if err != nil {
				t.Fatalf("resolveUDPAddr(%q): unexpected error: %v", network, err)
			}
			if got.Zone != wantZone {
				t.Errorf("Zone = %q, want %q", got.Zone, wantZone)
			}
			if !got.IP.Equal(wantIP) {
				t.Errorf("IP = %v, want %v", got.IP, wantIP)
			}
			if got.Port != wantPort {
				t.Errorf("Port = %d, want %d", got.Port, wantPort)
			}
			if want := "[fe80::1%en0]:4242"; got.String() != want {
				t.Errorf("String() = %q, want %q", got.String(), want)
			}
		})
	}
}

// TestResolveUDPAddrMatchesResolveUDPAddr pins resolveUDPAddr to the behavior of
// net.ResolveUDPAddr, which it replaces solely to accept a context. Only IP
// literals are used so the test never touches the network.
func TestResolveUDPAddrMatchesResolveUDPAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		network string
		addr    string
	}{
		{"ipv4 literal, udp4", "udp4", "198.51.100.9:41641"},
		{"ipv4 literal, udp", "udp", "198.51.100.9:41641"},
		{"ipv6 literal, udp6", "udp6", "[2001:db8::5]:41641"},
		{"ipv6 literal, udp", "udp", "[2001:db8::5]:41641"},
		{"scoped ipv6 literal, udp6", "udp6", "[fe80::1%en0]:4242"},
		{"scoped ipv6 literal, udp", "udp", "[fe80::1%en0]:4242"},
		{"ipv4-mapped literal, udp", "udp", "[::ffff:198.51.100.9]:41641"},
		{"no host", "udp", ":41641"},
		{"ipv6 literal rejected by udp4", "udp4", "[::1]:9000"},
		{"ipv4-mapped rejected by udp6", "udp6", "[::ffff:198.51.100.9]:9000"},
		{"ipv4 literal rejected by udp6", "udp6", "198.51.100.9:9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want, wantErr := net.ResolveUDPAddr(tt.network, tt.addr)
			got, gotErr := resolveUDPAddr(context.Background(), net.DefaultResolver, tt.network, tt.addr)

			if (gotErr != nil) != (wantErr != nil) {
				t.Fatalf("error mismatch: got %v, net.ResolveUDPAddr got %v", gotErr, wantErr)
			}
			if wantErr != nil {
				if gotErr.Error() != wantErr.Error() {
					t.Fatalf("error = %q, want %q", gotErr, wantErr)
				}
				return
			}

			if got.String() != want.String() {
				t.Errorf("String() = %q, want %q", got.String(), want.String())
			}
			if !got.IP.Equal(want.IP) {
				t.Errorf("IP = %v, want %v", got.IP, want.IP)
			}
			if len(got.IP) != len(want.IP) {
				t.Errorf("len(IP) = %d, want %d", len(got.IP), len(want.IP))
			}
			if got.Zone != want.Zone {
				t.Errorf("Zone = %q, want %q", got.Zone, want.Zone)
			}
			if got.Port != want.Port {
				t.Errorf("Port = %d, want %d", got.Port, want.Port)
			}
		})
	}
}
