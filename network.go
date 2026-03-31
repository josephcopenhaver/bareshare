package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// startPunch creates a separate UDP socket bound to the same local port
// (via SO_REUSEPORT) and punches continuously from it. This avoids writing
// to the QUIC transport's socket, which quic-go requires exclusive access to.
// The punch socket is closed when ctx is cancelled.
func startPunch(ctx context.Context, localPort int, remoteAddr string) error {
	target, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return err
	}

	punchConn, err := reuseListenUDP(localPort)
	if err != nil {
		return fmt.Errorf("punch socket: %w", err)
	}

	// First byte must have bits 6 and 7 clear (< 0x40) so quic-go's
	// IsPotentialQUICPacket/IsLongHeaderPacket reject it immediately
	// without entering the packet processing queue.
	payload := []byte{0x07, 'b', 's', 'p', 'u', 'n', 'c', 'h'}

	go func() {
		defer punchConn.Close()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				punchConn.WriteToUDP(payload, target)
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
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerFingerprint(rawCerts, expectedPeerFP)
		},
		NextProtos:         []string{cmdName},
		InsecureSkipVerify: true, // self-signed; we verify via fingerprint above
		MinVersion:         tls.VersionTLS13,
	}, nil
}

func listenQUIC(conn *net.UDPConn, tlsConf *tls.Config) (*quic.Listener, *quic.Transport, error) {
	tr := &quic.Transport{Conn: conn}
	ln, err := tr.Listen(tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	return ln, tr, nil
}

func dialQUIC(ctx context.Context, timeout time.Duration, conn *net.UDPConn, remoteAddr string, tlsConf *tls.Config) (*quic.Conn, *quic.Transport, error) {
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	tr := &quic.Transport{Conn: conn}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	qconn, err := tr.Dial(ctx, addr, tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	return qconn, tr, nil
}
