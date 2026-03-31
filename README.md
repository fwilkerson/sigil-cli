# sigil

Cryptographically-signed trust scores for AI agent tools.

Sigil lets you check how trustworthy a tool is before your AI agent uses it,
submit attestations after use, and browse the community trust leaderboard.
Your identity is a DID (decentralized identifier) created automatically on
first use.

## Install

```sh
curl -fsSL https://sigil-trust.dev/install.sh | sh
```

Or build from source:

```sh
go install github.com/fwilkerson/sigil-cli@latest
```

## Quick start

```sh
# Check a tool's trust score
sigil trust check https://github.com/anthropics/claude-code

# Submit an attestation after using a tool
sigil trust attest https://github.com/anthropics/claude-code

# View the trust leaderboard
sigil trust top

# Show your identity
sigil identity show
```

## Commands

| Command | Description |
|---|---|
| `sigil trust check <tool-uri>` | Check a tool's trust score |
| `sigil trust attest <tool-uri>` | Submit a positive or negative attestation |
| `sigil trust retract <tool-uri>` | Retract a previous attestation |
| `sigil trust top` | View the top-trusted tools leaderboard |
| `sigil trust config <key> <value>` | Configure CLI behavior (e.g. `auto-attest`) |
| `sigil identity show` | Display your DID and public key |
| `sigil version` | Show version and build info |

## How it works

Sigil uses decentralized identifiers (DIDs) and Ed25519 signatures to build
a community-driven trust layer for AI agent tooling. When you attest to a
tool, your signed attestation is submitted to the
[Sigil Trust Service](https://sigil-trust.dev) where it contributes to the
tool's aggregate trust score.

- Identities are generated locally and never leave your machine
- Attestations are cryptographically signed before submission
- Negative attestations require interactive confirmation
- Offline attestations are queued and submitted on next connection

## License

MIT
