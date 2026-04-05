package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
)

const (
	toolName = "BareShare"
	cmdName  = "bareshare"
)

func usage() {
	fmt.Printf(`
%s - Secure P2P File Transfer

Usage:
  %s show-key
  %s rotate-key
  %s send    --file <path> --to <host:port> --peer-key <fingerprint> [--port <port>]
  %s receive --peer-key <fingerprint> [--port <port>] [--out <file>] [--mode <octal>] [--key-file <path|.>] [--resume] [--sender-addr <host:port>]

Modes:
  show-key     Display your public key fingerprint (SHA-256 of SPKI)
  rotate-key   Generate a new key pair, replacing the existing one
  send         Send a file to a verified peer over QUIC
  receive      Listen for an incoming file from a verified peer

Security:
  - ECDSA P-384 (NIST FIPS 186-5) key pair, stored in ~/.%s/
  - Mutual TLS 1.3 over QUIC (UDP) with peer fingerprint verification
  - NAT traversal with bilateral UDP hole punching

`, toolName, cmdName, cmdName, cmdName, cmdName, cmdName)
}

func helpFlagInArgs(args ...string) bool {

	for _, arg := range args {
		if arg == "--help" || arg == "-help" || arg == "-h" {
			return true
		}
	}

	return false
}

func main() {
	ctx := context.Background()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	k := os.Args[1]

	switch k {
	case "show-key", "rotate-key", "send", "receive":
		// do nothing
	default:
		usage()

		if os.Args[1] == "help" || helpFlagInArgs(os.Args[1:]...) {
			os.Exit(0)
		}

		os.Exit(1)
	}

	switch k {
	case "show-key":
		cmdShowKey()
	case "rotate-key":
		cmdRotateKey()
	case "send":
		cmdSend(ctx)
	case "receive":
		cmdReceive(ctx)
	default:
		panic("unreachable")
	}
}

func cmdShowKey() {
	key, err := loadOrCreateKey()
	if err != nil {
		panic(fmt.Errorf("load key: %w", err))
	}
	fmt.Printf("Your public key fingerprint:\n%s\n", fingerprint(&key.PublicKey))
}

func cmdRotateKey() {
	newKey, oldFP, err := rotateKey()
	if err != nil {
		panic(fmt.Errorf("rotate key: %w", err))
	}
	if oldFP != "" {
		fmt.Printf("Old fingerprint: %s\n", oldFP)
	}
	fmt.Printf("New fingerprint: %s\nKey pair rotated. Share the new fingerprint with your peers.\n", fingerprint(&newKey.PublicKey))
}

func cmdSend(ctx context.Context) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to file to send")
	to := fs.String("to", "", "Receiver address (host:port)")
	peerKey := fs.String("peer-key", "", "Expected receiver fingerprint")
	port := fs.Int("port", 0, "Local UDP port (0 = random, set for bilateral punch)")
	fs.Parse(os.Args[2:])

	if *filePath == "" || *to == "" || *peerKey == "" {
		err := errors.New("required: --file, --to, --peer-key")
		panic(err)
	}

	key, err := loadOrCreateKey()
	if err != nil {
		panic(fmt.Errorf("load key: %w", err))
	}

	fmt.Fprintf(os.Stderr, "Your fingerprint: %s\n", fingerprint(&key.PublicKey))
	fmt.Fprintf(os.Stderr, "Connecting to %s...\n", *to)

	if err := sendFile(ctx, key, *filePath, *to, *peerKey, *port); err != nil {
		panic(fmt.Errorf("send file: %w", err))
	}
}

func cmdReceive(ctx context.Context) {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	port := fs.Int("port", 0, "UDP port to listen on")
	peerKey := fs.String("peer-key", "", "Expected sender fingerprint")
	outDir := fs.String("out", "-", "Output file path (default: stdout)")
	modeStr := fs.String("mode", "0666", "File permission mode (octal, e.g. 0600)")
	keyFile := fs.String("key-file", "", "Key file path (default: ephemeral, '.': user key)")
	resume := fs.Bool("resume", false, "Resume an interrupted download")
	senderAddr := fs.String("sender-addr", "", "Sender's public address for bilateral hole punching")
	fs.Parse(os.Args[2:])

	if *peerKey == "" {
		err := errors.New("required: --peer-key")
		panic(err)
	}
	switch *outDir {
	case "":
		err := errors.New("Output path cannot be empty: invalid value for --out")
		panic(err)
	case "-":
		if *resume {
			err := errors.New("--resume is not supported when output is stdout")
			panic(err)
		}
	}

	parsed, err := strconv.ParseUint(*modeStr, 8, 32)
	if err != nil {
		panic(fmt.Errorf("invalid --mode %q: %w", *modeStr, err))
	}
	mode := os.FileMode(parsed)

	var key *ecdsa.PrivateKey
	switch *keyFile {
	case "":
		k, err := generateEphemeralKey()
		if err != nil {
			panic(fmt.Errorf("ephemeral key: %w", err))
		}
		key = k
		fmt.Fprintln(os.Stderr, "Using ephemeral key pair (one-time use)")
	case ".":
		k, err := loadOrCreateKey()
		if err != nil {
			panic(fmt.Errorf("load key: %w", err))
		}
		key = k
	default:
		k, err := loadKeyFromFile(*keyFile)
		if err != nil {
			panic(fmt.Errorf("load key file: %w", err))
		}
		key = k
	}

	fmt.Fprintf(os.Stderr, "Your fingerprint: %s\n", fingerprint(&key.PublicKey))

	if err := receiveFile(ctx, key, *port, *peerKey, *outDir, mode, *senderAddr, *resume); err != nil {
		panic(fmt.Errorf("receive file: %w", err))
	}
}
