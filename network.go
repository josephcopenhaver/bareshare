package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

// First byte must have bits 6 and 7 clear (< 0x40) so quic-go's
// IsPotentialQUICPacket/IsLongHeaderPacket reject it immediately
// without entering the packet processing queue.
const punchPayload = "\x07bspunch"

func resolver() *net.Resolver {
	return net.DefaultResolver
}

// resolveUDPAddr exists because net.ResolveUDPAddr does not take a context.
func resolveUDPAddr(ctx context.Context, resolver *net.Resolver, network, remoteAddr string) (*net.UDPAddr, error) {

	host, service, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, err
	}

	port, err := resolver.LookupPort(ctx, network, service)
	if err != nil {
		return nil, err
	}

	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if ip := net.IP(addr.AsSlice()).To16(); ip != nil {

			// mirrors net.ipv4only and net.ipv6only, which rejects IPv4-mapped
			switch network {
			case "udp4":
				if ip.To4() == nil {
					return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
				}
			case "udp6":
				if ip.To4() != nil {
					return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
				}
			}

			return &net.UDPAddr{IP: ip, Port: port, Zone: addr.Zone()}, nil
		}
	}

	var ipNet string
	switch network {
	case "udp4":
		ipNet = "ip4"
	case "udp6":
		ipNet = "ip6"
	default:
		ipNet = "ip"
	}

	ipAddrs, err := resolver.LookupNetIP(ctx, ipNet, host)
	if err != nil {
		return nil, err
	}

	if len(ipAddrs) == 0 {
		return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
	}

	// net.ResolveUDPAddr (addrList.forResolve) prefers IPv4 when the network
	// is "udp" and the host is not an IPv6 literal. LookupNetIP instead
	// returns RFC 6724 order, which puts IPv6 first wherever IPv6 connectivity
	// exists. Keep the old preference so the punch target matches the family
	// that the peer dials.
	ipAddr := ipAddrs[0].Unmap()
	if ipNet == "ip" && !ipAddr.Is4() {
		for _, v := range ipAddrs[1:] {
			v = v.Unmap()
			if v.Is4() {
				ipAddr = v
				break
			}
		}
	}

	target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ipAddr, uint16(port)))

	return target, nil
}

// startPunch punches continuously toward remoteAddr from the QUIC
// transport's own socket via Transport.WriteTo, so the punch shares the
// port used for the transfer without a second socket. Punching stops when
// ctx is cancelled.
func startPunch(ctx context.Context, tr *quic.Transport, network, remoteAddr string) (context.CancelFunc, error) {

	target, err := resolveUDPAddr(ctx, resolver(), network, remoteAddr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	doneChan := ctx.Done()
	waitChan := make(chan struct{})

	go func() {
		defer close(waitChan)

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-doneChan:
				return
			default:
			}

			select {
			case <-doneChan:
				return
			case <-ticker.C:
				tr.WriteTo([]byte(punchPayload), target)
			}
		}
	}()

	return func() {
		fmt.Fprintln(os.Stderr, "Stopping punches...")

		cancel()
		<-waitChan

		fmt.Fprintln(os.Stderr, "Punches stopped.")
	}, nil
}

// serverTLSConfig creates a TLS 1.3 config for the QUIC listener (receiver).
// It requires a client certificate and verifies the peer's fingerprint.
func serverTLSConfig(key *ecdsa.PrivateKey, expectedPeerFP string) (*tls.Config, error) {
	cert, err := makeTLSCert(key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // the only PQ-hybrid Go ships today
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerFingerprint(rawCerts, expectedPeerFP)
		},
		NextProtos: []string{cmdName},
		MinVersion: tls.VersionTLS13,
	}, nil
}

// clientTLSConfig creates a TLS 1.3 config for the QUIC dialer (sender).
// It presents a client certificate and verifies the server's fingerprint.
func clientTLSConfig(key *ecdsa.PrivateKey, expectedPeerFP string) (*tls.Config, error) {
	cert, err := makeTLSCert(key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // the only PQ-hybrid Go ships today
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerFingerprint(rawCerts, expectedPeerFP)
		},
		NextProtos:         []string{cmdName},
		InsecureSkipVerify: true, // self-signed; we verify via fingerprint above
		MinVersion:         tls.VersionTLS13,
	}, nil
}

func listenQUIC(tr *quic.Transport, tlsConf *tls.Config) (*quic.Listener, error) {
	return tr.Listen(tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
}

func dialQUIC(ctx context.Context, timeout time.Duration, tr *quic.Transport, network, remoteAddr string, tlsConf *tls.Config) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, err := resolveUDPAddr(ctx, resolver(), network, remoteAddr)
	if err != nil {
		return nil, err
	}

	return tr.Dial(ctx, addr, tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
}
