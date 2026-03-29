# BareShare

<!--
![tests](https://github.com/josephcopenhaver/bareshare/actions/workflows/tests.yaml/badge.svg)
![code-coverage](https://img.shields.io/badge/code_coverage-100%25-rgb%2852%2C208%2C88%29)
-->
[![Go Report Card](https://goreportcard.com/badge/github.com/josephcopenhaver/bareshare)](https://goreportcard.com/report/github.com/josephcopenhaver/bareshare)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Secure peer-to-peer file transfer over QUIC with mutual TLS 1.3 and ECDSA P-384 identity verification. No servers, no accounts, no plaintext.

## How it works

Both peers identify themselves with an ECDSA P-384 key pair. Before connecting, each side obtains the other's public key fingerprint (SHA-256 of the SPKI-encoded public key) out of band — over Signal, a phone call, in person, etc. The connection is refused if either fingerprint doesn't match.

All traffic travels over QUIC (UDP), which requires TLS 1.3. Session keys are negotiated ephemerally, so recorded traffic cannot be decrypted even if a long-term key is later compromised.

## Installation

```sh
go install github.com/josephcopenhaver/bareshare@latest
```

Requires Go 1.25+. Linux and macOS are supported.

## Quick start

**On the receiving side:**

```sh
bareshare receive --peer-key <sender-fingerprint> --out file.tar.gz
```

This prints your fingerprint. Send it to the sender out of band.

**On the sending side:**

```sh
bareshare send --file file.tar.gz --to <host:port> --peer-key <receiver-fingerprint>
```

That's it. The connection is established only after both sides verify the other's fingerprint.

## Key management

Your persistent key pair is stored in `~/.bareshare/key.pem` (mode `0600`) and created automatically on first use.

```sh
# Print your public key fingerprint
bareshare show-key

# Generate a new key pair (old fingerprint is printed for reference)
bareshare rotate-key
```

Share your fingerprint with peers over a trusted channel. When you rotate, notify peers so they can update their `--peer-key` values.

## Receiver key modes

The receiver has three key options, controlled by `--key-file`:

| Flag | Behavior |
|------|----------|
| _(omitted)_ | Generate an ephemeral key for this transfer only. Never written to disk. |
| `--key-file .` | Use the persistent key from `~/.bareshare/key.pem`. |
| `--key-file <path>` | Use the key at the given path. |

**Ephemeral (default):** The receiver's fingerprint is fresh for each transfer. The sender must obtain it right before connecting. Nothing persists after the transfer.

**Persistent (`--key-file .`):** The sender can pin the receiver's fingerprint once and reuse it across transfers without re-exchanging it each time.

## NAT traversal

For peers behind NAT, use bilateral UDP hole punching. Both sides must use a fixed port and know each other's public address.

Use the port values you prefer. The receiver will use a random port if not specified.

**Receiver:**
```sh
bareshare receive --port 9990 --sender-addr <sender-public-ip:9999> --peer-key <fp> --out file.tar.gz
```

**Sender:**
```sh
bareshare send --port 9999 --to <receiver-public-ip:9990> --peer-key <fp> --file file.tar.gz
```

Both sides punch toward each other before the QUIC handshake begins.

## Resuming interrupted transfers

If a transfer is interrupted, the receiver can resume from where it left off:

```sh
bareshare receive --peer-key <sender-public-key> --out file.tar.gz --resume
```

Progress is tracked in two sidecar files next to the output path:
- `.file.tar.gz.dl.tmp` — partial data
- `.file.tar.gz.dl.status.json` — byte count and expected size

These are removed automatically on successful completion.

`--resume` requires a file output path (not stdout).

## Security model

- **Identity:** ECDSA P-384 key pair. Fingerprint is SHA-256 of the SPKI-encoded public key, base64url-encoded.
- **Authentication:** Mutual TLS certificate pinning. Both sides verify each other's fingerprint before any data flows. A mismatch aborts the connection.
- **Encryption:** TLS 1.3 over QUIC (enforced minimum version). Session keys are ephemeral — forward secrecy is guaranteed.
- **Trust anchor:** Fingerprints must be exchanged out of band. There is no CA, no TOFU, and no way to connect without knowing the peer's fingerprint in advance.

The security of a transfer is only as strong as the channel used to exchange fingerprints. Use a channel you trust.

## Reference

```
bareshare show-key
bareshare rotate-key
bareshare send    --file <path> --to <host:port> --peer-key <fingerprint> [--port <port>]
bareshare receive --peer-key <fingerprint> [--port <port>] [--out <path>] [--mode <octal>]
                  [--key-file <path|.>] [--resume] [--sender-addr <host:port>]
```
