package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
)

const (
	toolName = "BareShare"
	cmdName  = "bareshare"
)

// usageText is the help menu. It is a function rather than a constant so the
// completion tests can parse it: the modes and flags it documents must match
// what completion offers.
func usageText() string {
	return fmt.Sprintf(`
%[1]s - Secure P2P File Transfer
(%[2]s)

Usage:
  %[3]s show-key
  %[3]s rotate-key
  %[3]s send    --file <path> --to <host:port> --peer-key <fingerprint> [--port <port>] [--network <udp4|udp6|udp>]
  %[3]s receive --peer-key <fingerprint> [--port <port>] [--out <file>] [--mode <octal>] [--key-file <path|.>] [--resume] [--sender-addr <host:port>] [--network <udp4|udp6|udp>]
  %[3]s completion <bash|zsh>

Modes:
  show-key     Display your public key fingerprint (SHA-256 of SPKI)
  rotate-key   Generate a new key pair, replacing the existing one
  send         Send a file to a verified peer over QUIC
  receive      Listen for an incoming file from a verified peer
  version      Prints the version of this command.
  completion   Prints the tab completion script for bash or zsh
  help         Prints this help menu.

Shell completion:
  eval "$(%[3]s completion bash)"   # in ~/.bashrc
  . <(%[3]s completion zsh)         # in ~/.zshrc, after compinit

Security:
  - ECDSA P-384 (NIST FIPS 186-5) key pair for identity, stored in ~/.%[3]s/
  - Mutual TLS 1.3 over QUIC (UDP) with peer fingerprint verification
  - Key agreement pinned to X25519MLKEM768
  - NAT traversal with bilateral UDP hole punching

`, toolName, version, cmdName)
}

func usage() {
	fmt.Print(usageText())
}

// validNetwork verifies the --network flag value before any I/O starts.
func validNetwork(network string) error {
	switch network {
	case "udp4", "udp6", "udp":
		return nil
	}
	return fmt.Errorf("invalid --network %q: must be udp4, udp6, or udp", network)
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
	case "show-key", "rotate-key", "send", "receive", "version", "completion", "--complete":
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
	case "version":
		cmdVersion(ctx)
	case "completion":
		cmdCompletion()
	case "--complete": // hidden: the feed the generated completion scripts read
		cmdComplete()
	default:
		panic("unreachable")
	}
}

// cmdCompletion prints the shell integration the user evals or sources into
// their shell. Every failure is reported as sourceable shell code on stdout
// (see writeCompletion), so nothing but the exit status is left for this
// function.
func cmdCompletion() {
	if err := writeCompletion(os.Stdout, os.Args[2:]); err != nil {
		if !errors.Is(err, errSilent) {
			fmt.Fprintf(os.Stderr, "%s: %v\n", cmdName, err)
		}
		os.Exit(1)
	}
}

// cmdComplete answers the completion scripts' hidden protocol. The scripts
// discard stderr, so an error here only needs to be visible to someone
// driving the protocol by hand.
func cmdComplete() {
	if err := writeComplete(os.Stdout, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmdName, err)
		os.Exit(1)
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

// sendOpts are the parsed flags of the send mode.
type sendOpts struct {
	filePath string
	to       string
	peerKey  string
	port     int
	network  string
}

// sendFlags defines the send mode's flags. It is the single place they are
// declared: cmdSend parses them from here, and TestCompletionCatalogue_
// MatchesTheFlagSets checks the completion catalogue against them.
func sendFlags() (*flag.FlagSet, *sendOpts) {
	o := &sendOpts{}
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	fs.StringVar(&o.filePath, "file", "", "Path to file to send")
	fs.StringVar(&o.to, "to", "", "Receiver address (host:port)")
	fs.StringVar(&o.peerKey, "peer-key", "", "Expected receiver fingerprint")
	fs.IntVar(&o.port, "port", 0, "Local UDP port (0 = random, set for bilateral punch)")
	fs.StringVar(&o.network, "network", "udp4", "Bind network: udp4, udp6, or udp (dual-stack)")
	return fs, o
}

// receiveOpts are the parsed flags of the receive mode.
type receiveOpts struct {
	port       int
	peerKey    string
	outDir     string
	modeStr    string
	keyFile    string
	resume     bool
	senderAddr string
	network    string
}

// receiveFlags defines the receive mode's flags; see sendFlags.
func receiveFlags() (*flag.FlagSet, *receiveOpts) {
	o := &receiveOpts{}
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	fs.IntVar(&o.port, "port", 0, "UDP port to listen on")
	fs.StringVar(&o.peerKey, "peer-key", "", "Expected sender fingerprint")
	fs.StringVar(&o.outDir, "out", "-", "Output file path (default: stdout)")
	fs.StringVar(&o.modeStr, "mode", "0666", "File permission mode (octal, e.g. 0600)")
	fs.StringVar(&o.keyFile, "key-file", "", "Key file path (default: ephemeral, '.': user key)")
	fs.BoolVar(&o.resume, "resume", false, "Resume an interrupted download")
	fs.StringVar(&o.senderAddr, "sender-addr", "", "Sender's public address for bilateral hole punching")
	fs.StringVar(&o.network, "network", "udp4", "Bind network: udp4, udp6, or udp (dual-stack)")
	return fs, o
}

// modeFlagSets maps every mode that parses flags to its FlagSet constructor,
// so a test can enumerate the real flags without running the mode.
var modeFlagSets = map[string]func() *flag.FlagSet{
	"send":    func() *flag.FlagSet { fs, _ := sendFlags(); return fs },
	"receive": func() *flag.FlagSet { fs, _ := receiveFlags(); return fs },
}

func cmdSend(ctx context.Context) {
	fs, o := sendFlags()

	// note: error check not required: using flag.ExitOnError
	fs.Parse(os.Args[2:])

	if o.filePath == "" || o.to == "" || o.peerKey == "" {
		panic("required: --file, --to, --peer-key")
	}
	if err := validNetwork(o.network); err != nil {
		panic(err)
	}

	key, err := loadOrCreateKey()
	if err != nil {
		panic(fmt.Errorf("load key: %w", err))
	}

	fmt.Fprintf(os.Stderr, "Your fingerprint: %s\n", fingerprint(&key.PublicKey))
	fmt.Fprintf(os.Stderr, "Connecting to %s...\n", o.to)

	if err := sendFile(ctx, key, o.filePath, o.to, o.peerKey, o.port, o.network); err != nil {
		panic(fmt.Errorf("send file: %w", err))
	}
}

func cmdReceive(ctx context.Context) {
	fs, o := receiveFlags()

	// note: error check not required: using flag.ExitOnError
	fs.Parse(os.Args[2:])

	if o.peerKey == "" {
		panic("required: --peer-key")
	}
	if err := validNetwork(o.network); err != nil {
		panic(err)
	}
	switch o.outDir {
	case "":
		panic("output path cannot be empty: invalid value for --out")
	case "-":
		if o.resume {
			panic("--resume is not supported when output is stdout")
		}
	}

	parsed, err := strconv.ParseUint(o.modeStr, 8, 32)
	if err != nil {
		panic(fmt.Errorf("invalid --mode %q: %w", o.modeStr, err))
	}
	mode := os.FileMode(parsed)

	if runtime.GOOS == "windows" {
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "mode" {
				fmt.Fprintln(os.Stderr, "Warning: Unix permission modes map to Windows only as a best-effort (read-only attribute); --mode does not restrict access by other users")
			}
		})
	}

	var key *ecdsa.PrivateKey
	switch o.keyFile {
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
		k, err := loadKeyFromFile(o.keyFile)
		if err != nil {
			panic(fmt.Errorf("load key file: %w", err))
		}
		key = k
	}

	fmt.Fprintf(os.Stderr, "Your fingerprint: %s\n", fingerprint(&key.PublicKey))

	if err := receiveFile(ctx, key, o.port, o.peerKey, o.outDir, mode, o.senderAddr, o.resume, o.network); err != nil {
		panic(fmt.Errorf("receive file: %w", err))
	}
}

func cmdVersion(ctx context.Context) {
	fmt.Fprintf(os.Stdout, "%s\n", version)
}
