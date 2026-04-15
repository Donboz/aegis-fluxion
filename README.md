# aegis-fluxion

A production-oriented, TypeScript-first secure transport toolkit for WebSocket-based systems.

`aegis-fluxion` delivers **end-to-end encrypted messaging** with **zero external cryptography dependencies** (built entirely on native Node.js `crypto`) and is designed to serve as a hardened custom transport layer for AI agent communication, including **Anthropic MCP (Model Context Protocol)** integrations.

## Table of Contents

- [Why aegis-fluxion](#why-aegis-fluxion)
- [Security Model](#security-model)
- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Secure Server](#secure-server)
  - [Secure Client](#secure-client)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [MCP and AI Agent Use Cases](#mcp-and-ai-agent-use-cases)
- [Operational Notes](#operational-notes)
- [Roadmap](#roadmap)
- [License](#license)

## Why aegis-fluxion

Most agent and tool protocols rely on transport-level TLS only. TLS is necessary but not always sufficient for multi-hop infrastructure, long-lived sessions, proxy chains, or custom gateway topologies.

`aegis-fluxion` adds a protocol-level security layer directly in your WebSocket event flow:

- Per-connection ephemeral key exchange
- Derived symmetric session keys
- Authenticated encryption for every application packet
- Transparent developer API (`emit` / `on`) without cryptographic ceremony in business code

## Security Model

- **Key Exchange**: Ephemeral ECDH (`prime256v1`) on each connection
- **Key Derivation**: SHA-256 derivation to guaranteed 32-byte AES key material
- **Payload Encryption**: AES-256-GCM with per-message random IV (`12 bytes`)
- **Integrity and Tamper Detection**: GCM authentication tag validation on receive
- **Anti-Tampering Behavior**: Modified packets are dropped and never dispatched to user handlers
- **Secret Hygiene**: No private keys or shared secrets are logged
- **Memory Safety**: Connection-scoped secret material is cleared when socket disconnects

## Key Features

- E2E encrypted event transport over WebSocket
- Socket.IO-like developer ergonomics with `emit(event, data)` and `on(event, handler)`
- Handshake and encryption logic hidden behind a stable public API
- Ready-gating: user-level traffic is blocked/queued until secure session is established
- TypeScript-native event handler and options typing
- Vitest integration tests for normal encrypted flow and tamper rejection behavior

## Architecture Overview

`aegis-fluxion` is currently organized as a workspace monorepo.

```text
.
├── package.json
└── packages/
    └── core/
        ├── src/
        │   └── index.ts
        ├── test/
        │   └── index.test.ts
        ├── tsconfig.json
        └── tsup.config.ts
```

## Installation

### Monorepo (current repository)

```bash
npm install
npm run build
```

### Package usage (when published)

```bash
npm install @aegis-fluxion/core ws
```

> Note: The cryptographic layer itself has no third-party crypto dependency. The transport runtime depends on `ws`.

## Quick Start

### Secure Server

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080
});

server.on("connection", (client) => {
  console.log(`Client connected: ${client.id}`);
});

server.on("ready", (client) => {
  console.log(`Secure session established: ${client.id}`);
});

server.on("task", (payload, client) => {
  // Business payload is already decrypted and integrity-validated.
  server.emitTo(client.id, "task:ack", { ok: true, received: payload });
});

server.on("disconnect", (client, code, reason) => {
  console.log(`Client disconnected: ${client.id} (${code} ${reason})`);
});

server.on("error", (error) => {
  console.error("Secure server error:", error.message);
});
```

### Secure Client

```ts
import { SecureClient } from "@aegis-fluxion/core";

const client = new SecureClient("ws://127.0.0.1:8080", {
  autoConnect: true
});

client.on("connect", () => {
  console.log("Socket connected. Waiting for secure ready state...");
});

client.on("ready", () => {
  console.log("Secure channel ready.");
  client.emit("task", { id: "job-1", action: "run" });
});

client.on("task:ack", (payload) => {
  console.log("Encrypted response received:", payload);
});

client.on("disconnect", (code, reason) => {
  console.log(`Disconnected: ${code} ${reason}`);
});

client.on("error", (error) => {
  console.error("Secure client error:", error.message);
});
```

## How It Works

1. Server accepts connection.
2. Both sides generate ephemeral ECDH key pairs.
3. Internal handshake (`__handshake`) exchanges public keys.
4. Both sides compute shared secret and derive a 32-byte session key.
5. `ready` event is emitted.
6. All user messages are encrypted as:
   - `version (1 byte)`
   - `iv (12 bytes)`
   - `authTag (16 bytes)`
   - `ciphertext (N bytes)`
7. Receiver validates auth tag before dispatching user events.

If validation fails, the payload is dropped and not delivered to user handlers.

## Testing

Run all validation commands:

```bash
npm run typecheck
npm run test
npm run build
```

Current test coverage includes:

- Successful encrypted communication between `SecureClient` and `SecureServer`
- Tampered packet rejection (Auth Tag failure path) without transport crash

## Project Structure

- `packages/core/src/index.ts`
  - Secure transport implementation
  - ECDH handshake
  - AES-256-GCM encryption/decryption
  - Public TypeScript types and classes
- `packages/core/test/index.test.ts`
  - Integration-style security flow tests

## MCP and AI Agent Use Cases

`aegis-fluxion` is a practical fit for AI infrastructure where transport hardening matters:

- Anthropic MCP gateway-to-agent links
- Multi-agent orchestration over WebSocket
- Tooling backplanes where packet integrity must be enforced
- Custom secure transport adapters for model runtime services

By keeping the cryptography layer protocol-native and API-transparent, teams can integrate secure transport without rewriting agent/business logic.

## Operational Notes

- This package secures message payloads at the application protocol layer.
- You should still use TLS (`wss://`) in production for transport confidentiality and endpoint authentication.
- Rate limiting, authentication, and authorization are complementary controls and should be implemented at gateway/service boundaries.

## Roadmap

- Key rotation and re-key policies
- Replay protection primitives
- AAD binding options for stronger protocol context integrity
- Optional observability hooks with secure redaction defaults

## License

This repository currently does not define a license file.
Add a `LICENSE` (for example MIT, Apache-2.0, or proprietary terms) before publishing publicly.
