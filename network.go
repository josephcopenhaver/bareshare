package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// startPunch punches continuously toward remoteAddr from the QUIC
// transport's own socket via Transport.WriteTo, so the punch shares the
// port used for the transfer without a second socket. Punching stops when
// ctx is cancelled.
func startPunch(ctx context.Context, tr *quic.Transport, network, remoteAddr string) error {
	target, err := net.ResolveUDPAddr(network, remoteAddr)
	if err != nil {
		return err
	}

	// First byte must have bits 6 and 7 clear (< 0x40) so quic-go's
	// IsPotentialQUICPacket/IsLongHeaderPacket reject it immediately
	// without entering the packet processing queue.
	payload := []byte{0x07, 'b', 's', 'p', 'u', 'n', 'c', 'h'}

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tr.WriteTo(payload, target)
			}
		}
	}()

	return nil
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
	addr, err := net.ResolveUDPAddr(network, remoteAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return tr.Dial(ctx, addr, tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
}
