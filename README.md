# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.3.0-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is a secure WebSocket toolkit for TypeScript/Node.js applications that need **application-layer encryption**, **secure room broadcasting**, and now **transport resilience** with:

- **Server heartbeat (Ping/Pong)** to detect and terminate zombie sockets
- **Automatic in-memory key cleanup** for dead connections
- **Client auto-reconnect with exponential backoff**
- **Fresh handshake/tunnel establishment after reconnect**

---

## Table of Contents

- [What’s New in v0.3.0](#whats-new-in-v030)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Secure Server](#secure-server)
  - [Secure Client](#secure-client)
- [Resilience & Reconnection](#resilience--reconnection)
  - [Server Heartbeat](#server-heartbeat)
  - [Client Auto-Reconnect](#client-auto-reconnect)
- [Secure Rooms](#secure-rooms)
- [Security Model](#security-model)
- [API Overview](#api-overview)
- [Development](#development)
- [License](#license)

---

## What’s New in v0.3.0

### 1) Heartbeat-based zombie cleanup (server)

The server now sends periodic Ping frames and tracks Pong acknowledgements.

If a socket becomes unresponsive, the server will:

1. terminate the zombie socket,
2. remove handshake/encryption material from memory,
3. release queued payload state,
4. trigger normal disconnect lifecycle.

### 2) Exponential backoff reconnect (client)

When the connection drops unexpectedly, the client now retries with configurable backoff:

- initial delay,
- factor,
- max delay,
- optional jitter,
- optional max attempts.

On each successful reconnect, the secure tunnel is rebuilt from scratch with a new ephemeral handshake.

---

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

---

## Quick Start

### Secure Server

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  heartbeat: {
    enabled: true,
    intervalMs: 15_000,
    timeoutMs: 15_000
  }
});

server.on("connection", (socket) => {
  console.log(`connected: ${socket.id}`);
  socket.join("agents:ops");
});

server.on("ready", (socket) => {
  console.log(`secure tunnel ready: ${socket.id}`);
  server.emitTo(socket.id, "session:ready", { ok: true });
});

server.on("chat:send", (payload, socket) => {
  server.to("agents:ops").emit("chat:message", {
    from: socket.id,
    body: payload
  });
});

server.on("disconnect", (socket, code, reason) => {
  console.log(`disconnected: ${socket.id} (${code} ${reason})`);
});

server.on("error", (error) => {
  console.error("server error:", error.message);
});
```

### Secure Client

```ts
import { SecureClient } from "@aegis-fluxion/core";

const client = new SecureClient("ws://127.0.0.1:8080", {
  autoConnect: true,
  reconnect: {
    enabled: true,
    initialDelayMs: 300,
    maxDelayMs: 10_000,
    factor: 2,
    jitterRatio: 0.2,
    maxAttempts: null // null => unlimited retries
  }
});

client.on("connect", () => {
  console.log("transport connected");
});

client.on("ready", () => {
  console.log("secure tunnel established");
  client.emit("chat:send", "hello from resilient client");
});

client.on("chat:message", (payload) => {
  console.log("secure room payload:", payload);
});

client.on("disconnect", (code, reason) => {
  console.log(`transport disconnected: ${code} ${reason}`);
});

client.on("error", (error) => {
  console.error("client error:", error.message);
});
```

---

## Resilience & Reconnection

### Server Heartbeat

Use heartbeat options in `SecureServer` constructor:

```ts
new SecureServer({
  port: 8080,
  heartbeat: {
    enabled: true,
    intervalMs: 10_000,
    timeoutMs: 12_000
  }
});
```

**Behavior**

- Every `intervalMs`, the server sends Ping to open sockets.
- If no Pong is received within `timeoutMs`, the socket is treated as zombie.
- The server terminates the socket and clears encryption-related state from RAM.

### Client Auto-Reconnect

Use reconnect options in `SecureClient` constructor:

```ts
new SecureClient("ws://127.0.0.1:8080", {
  reconnect: {
    enabled: true,
    initialDelayMs: 250,
    factor: 2,
    maxDelayMs: 10_000,
    jitterRatio: 0.2,
    maxAttempts: 25
  }
});
```

**Behavior**

- Reconnect is triggered after unintentional disconnect.
- Retry delay follows exponential backoff with optional jitter.
- On reconnect success, handshake is run again and a fresh encryption key is derived.
- Calling `client.disconnect()` is treated as manual stop (no auto-retry).

---

## Secure Rooms

Room APIs (server-side):

- `socket.join(room)`
- `socket.leave(room)`
- `socket.leaveAll()`
- `server.to(room).emit(event, data)`

Example:

```ts
server.on("connection", (socket) => {
  socket.join("alerts");
});

server.to("alerts").emit("alert:new", {
  severity: "high",
  message: "Integrity check failed on worker-07"
});
```

Room broadcast remains encrypted per recipient.

---

## Security Model

### Handshake

1. Client and server generate ephemeral ECDH keys (`prime256v1`).
2. Public keys are exchanged over internal handshake events.
3. Shared secret is derived independently on both sides.
4. AES-256-GCM key material is derived from SHA-256.

### Message Packet

Encrypted packet structure:

- `version` (1 byte)
- `iv` (12 bytes)
- `authTag` (16 bytes)
- `ciphertext` (N bytes)

Tampered encrypted payloads fail authentication and are dropped.

---

## API Overview

### `SecureServer`

- `on("connection" | "ready" | "disconnect" | "error", handler)`
- `on("custom:event", (data, socket) => void)`
- `emit(event, data)`
- `emitTo(clientId, event, data)`
- `to(room).emit(event, data)`
- `close(code?, reason?)`

### `SecureServerClient`

- `id: string`
- `socket: WebSocket`
- `join(room): boolean`
- `leave(room): boolean`
- `leaveAll(): number`

### `SecureClient`

- `connect()`
- `disconnect(code?, reason?)`
- `emit(event, data): boolean`
- `isConnected(): boolean`
- `readyState: number | null`
- `on("connect" | "ready" | "disconnect" | "error", handler)`
- `on("custom:event", handler)`

---

## Development

From repository root:

```bash
npm run typecheck
npm run test
npm run build
```

Project layout:

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

---

## License

MIT License.
