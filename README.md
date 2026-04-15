# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.2.0-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

Secure, production-ready WebSocket transport primitives for modern TypeScript systems.

`aegis-fluxion` provides **application-layer end-to-end encryption** and now includes **Secure Rooms** with Socket.IO-like ergonomics:

- `socket.join("room")`
- `socket.leave("room")`
- `server.to("room").emit("event", data)`

> Even when broadcasting to a room, each recipient receives a separately encrypted packet using that connection’s own ECDH-derived AES-GCM key.

## Table of Contents

- [Why aegis-fluxion](#why-aegis-fluxion)
- [What’s New in v0.2.0](#whats-new-in-v020)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Secure Server](#secure-server)
  - [Secure Client](#secure-client)
- [Secure Rooms](#secure-rooms)
- [Security Architecture](#security-architecture)
- [API Overview](#api-overview)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [AI & MCP Vision](#ai--mcp-vision)
- [Operational Notes](#operational-notes)
- [License](#license)

## Why aegis-fluxion

TLS is necessary, but for many systems it is not sufficient.

When traffic crosses proxies, gateways, sidecars, or long-lived internal meshes, application-level payload protection becomes essential.

`aegis-fluxion` adds protocol-native cryptographic guarantees directly into your event flow:

- Ephemeral ECDH handshake per connection (PFS-oriented)
- AES-256-GCM authenticated encryption for each message
- Tamper rejection by default
- Clean developer API with no cryptography boilerplate in business handlers

## What’s New in v0.2.0

### Secure Rooms

- Added server-side room membership management:
  - `socket.join(room)`
  - `socket.leave(room)`
  - `socket.leaveAll()`
- Added room-targeted emit API:
  - `server.to(room).emit(event, data)`

### Cryptographic Safety Preserved

Room broadcasts do **not** use a shared room key. Instead, the server encrypts per recipient, per packet, with that recipient’s own session key.

## Installation

### Monorepo (this repository)

```bash
npm install
npm run build
```

### Package usage

```bash
npm install @aegis-fluxion/core ws
```

> The cryptographic layer uses native Node.js `crypto` only (no third-party crypto package).

## Quick Start

### Secure Server

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080
});

server.on("connection", (socket) => {
  console.log(`Connected: ${socket.id}`);

  // Room assignment on connection
  socket.join("agents:ops");
});

server.on("ready", (socket) => {
  console.log(`Secure channel ready: ${socket.id}`);
  server.emitTo(socket.id, "session:ready", { ok: true });
});

server.on("chat:send", (payload, socket) => {
  // Route only to room members, still encrypted per recipient.
  server.to("agents:ops").emit("chat:message", {
    from: socket.id,
    body: payload
  });
});

server.on("disconnect", (socket, code, reason) => {
  console.log(`Disconnected: ${socket.id} (${code} ${reason})`);
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
  console.log("Transport connected, waiting for cryptographic ready...");
});

client.on("ready", () => {
  console.log("Secure channel established.");
  client.emit("chat:send", "hello secure room");
});

client.on("session:ready", (payload) => {
  console.log("Server session ack:", payload);
});

client.on("chat:message", (payload) => {
  console.log("Encrypted room message received:", payload);
});

client.on("disconnect", (code, reason) => {
  console.log(`Disconnected: ${code} ${reason}`);
});

client.on("error", (error) => {
  console.error("Secure client error:", error.message);
});
```

## Secure Rooms

Rooms are managed server-side and designed for strict encrypted delivery.

```ts
server.on("connection", (socket) => {
  socket.join("alerts");
});

// Later in business logic
server.to("alerts").emit("alert:new", {
  severity: "high",
  message: "Integrity check failed on worker-07"
});
```

Remove a socket from a room:

```ts
server.on("mute:alerts", (_, socket) => {
  socket.leave("alerts");
});
```

> No plaintext fan-out is performed for rooms. Each outbound payload is serialized and encrypted separately for each destination socket.

## Security Architecture

### Handshake

1. Client and server generate ephemeral ECDH keys (`prime256v1`).
2. Public keys are exchanged via internal handshake event.
3. Shared secret is derived on both ends.
4. AES key material is derived via SHA-256 (`32 bytes`).

### Packet Format

Every encrypted payload is structured as:

- `version` (1 byte)
- `iv` (12 bytes)
- `authTag` (16 bytes)
- `ciphertext` (N bytes)

### Confidentiality + Integrity

- Cipher: `AES-256-GCM`
- New IV per message
- Auth tag required for successful decryption
- Tampered payloads are dropped silently from business event dispatch

### Secure Rooms Guarantee

When `server.to(room).emit(...)` is called:

- The room membership set is resolved on server side.
- The same logical event is encrypted individually for each socket.
- Each encryption operation uses that socket’s own ECDH-derived session key.

This preserves E2E semantics for room broadcasts.

## API Overview

### `SecureServer`

- `on("connection", handler)`
- `on("ready", handler)`
- `on("disconnect", handler)`
- `on("error", handler)`
- `on("event", (data, socket) => void)`
- `emit(event, data)` (broadcast to all connected sockets)
- `emitTo(clientId, event, data)`
- `to(room).emit(event, data)`
- `close(code?, reason?)`

### `SecureServerClient` (socket object on server)

- `id: string`
- `join(room): boolean`
- `leave(room): boolean`
- `leaveAll(): number`

### `SecureClient`

- `connect()` / `disconnect(code?, reason?)`
- `emit(event, data)`
- `on("connect" | "ready" | "disconnect" | "error", handler)`
- `on("event", handler)`

## Testing

Run all checks from the repository root:

```bash
npm run typecheck
npm run test
npm run build
```

Current integration coverage includes:

- encrypted client/server exchange
- tampered packet rejection without transport crash
- secure rooms join/leave and room-scoped emits

## Project Structure

```text
.
├── package.json
├── README.md
└── packages/
    └── core/
        ├── src/
        │   └── index.ts
        ├── test/
        │   └── index.test.ts
        ├── tsconfig.json
        └── tsup.config.ts
```

## AI & MCP Vision

`aegis-fluxion` is built for systems that need cryptographically hardened event transport, including:

- AI agent backplanes
- MCP transport adapters
- multi-agent orchestration channels
- secure tool execution networks

By keeping security protocol-native and API-minimal, teams can integrate hardened messaging without rewriting application business logic.

## Operational Notes

- Use `wss://` in production (transport confidentiality + endpoint authentication).
- Application-layer encryption in `aegis-fluxion` complements TLS; it does not replace infrastructure security.
- Add authentication, authorization, and rate limiting at the edge/service layer.

## License

MIT License.
