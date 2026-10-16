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

Requires Go 1.27+. Linux, macOS, and Windows are supported.

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

The receiver punches toward the sender before the QUIC handshake begins. The
punch packets are sent from the same UDP socket QUIC uses, so the NAT mapping
they open is exactly the one the transfer flows through.

## Network selection

Both `send` and `receive` bind IPv4 (`udp4`) by default. Use `--network` to
opt into IPv6 or dual-stack operation:

| Value | Behavior |
|-------|----------|
| `udp4` _(default)_ | IPv4 only |
| `udp6` | IPv6 only |
| `udp` | Dual-stack (IPv4 and IPv6) |

Any other value is rejected at startup. Both peers must be reachable over the
address family in use; hole punching over IPv6 paths is uncommon since NAT is
rarely involved.

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

## Shell completion

```sh
eval "$(bareshare completion bash)"   # in ~/.bashrc
. <(bareshare completion zsh)         # in ~/.zshrc, AFTER compinit
```

The two forms differ on purpose. bash 3.2, which macOS still ships, reads
nothing when it sources a pipe, so `. <(...)` would silently install nothing
there; `eval` works in every bash. An interactive zsh, on the other hand, is
not obliged to treat `#` as a comment inside an `eval`, so the zsh integration
is sourced instead (and carries no comments at all, for the same reason).

Tab completes the mode at the first position (`send`, `receive`, `show-key`,
...), each mode's flags after it (a flag already on the line is not offered
again), files after `--file`, `--out` and `--key-file`, and `udp4`/`udp6`/`udp`
after `--network`. Both `--network udp4` and `--network=udp4` are understood.
Under zsh each mode and flag also carries its one-line description. Values only
you know — addresses, fingerprints, ports, modes — complete to nothing rather
than to a guess.

Completion never touches the key directory, so a tab press can never create a
key pair.

### How the shells stay in step

The argument grammar — what may appear at each position — lives once, in Go, in
`completion.go`. Both scripts are thin adapters over the hidden

```console
$ bareshare --complete zsh 3 -- bareshare send --network ''
words
udp4	IPv4 only (default)
udp6	IPv6 only
udp	dual-stack, IPv4 and IPv6
```

protocol: they hand bareshare the words typed so far and the index of the one
under the cursor, and translate the directive on the first line (`words`,
`files`, `none`) into `compgen`/`COMPREPLY` or `_describe`/`_files`.
Candidates come back unfiltered, so each shell applies its own matching —
including whatever `zstyle` matcher a zsh user has configured.

A second copy of that grammar written in shell would drift from the first and
could only be tested through a shell; this way `completionModes` in
`completion.go` is the single place a new mode or flag has to be declared, and
a test fails if it and the help menu ever disagree.

### Other shells

Only bash and zsh are implemented. Any other argument (or none) prints a
source-safe complaint instead of a script and exits non-zero:

```console
$ eval "$(bareshare completion fish)"; echo $?
fish not supported
1
```

The complaint is `>&2 echo "..." && false` rather than `... && exit 1`
deliberately: you are evaluating it in your interactive shell, where `exit`
would close the terminal (or abort the rest of your rc file). `false` still
leaves `$?` non-zero. The shell name is echoed back only when it is one
bareshare recognises; anything else reports `unknown shell specified`, so an
argument can never smuggle text into the eval.

## Security model

- **Identity:** ECDSA P-384 key pair. Fingerprint is SHA-256 of the SPKI-encoded public key, base64url-encoded.
- **Authentication:** Mutual TLS certificate pinning. Both sides verify each other's fingerprint before any data flows. A mismatch aborts the connection.
- **Encryption:** TLS 1.3 over QUIC (enforced minimum version). Session keys are ephemeral — forward secrecy is guaranteed.
- **Trust anchor:** Fingerprints must be exchanged out of band. There is no CA, no TOFU, and no way to connect without knowing the peer's fingerprint in advance.

The security of a transfer is only as strong as the channel used to exchange fingerprints. Use a channel you trust.

## Windows notes

- The key directory (`%USERPROFILE%\.bareshare`) and `key.pem` are protected with an explicit owner-only ACL (inheritance cut), the Windows equivalent of `0700`/`0600`. The file's ACL is part of the `CreateFile` call itself, so the key never exists on disk without it.
- Unix permission modes map to Windows only as a best-effort (write bit → read-only attribute). Passing `--mode` on Windows prints a warning; it does not restrict access by other users. Received files get the ACLs their directory grants them.
- The resume sidecar files (`.name.dl.tmp`, `.name.dl.status.json`) keep their dot-prefixed names but are not hidden by Windows Explorer.

## Reference

```
bareshare show-key
bareshare rotate-key
bareshare send    --file <path> --to <host:port> --peer-key <fingerprint> [--port <port>]
                  [--network <udp4|udp6|udp>]
bareshare receive --peer-key <fingerprint> [--port <port>] [--out <path>] [--mode <octal>]
                  [--key-file <path|.>] [--resume] [--sender-addr <host:port>]
                  [--network <udp4|udp6|udp>]
bareshare completion <bash|zsh>
```
