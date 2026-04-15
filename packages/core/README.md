# @aegis-fluxion/core

Core E2E-encrypted WebSocket primitives for `aegis-fluxion`.

Version: **0.4.0**

---

## Features

- ECDH handshake (`prime256v1`) with ephemeral key exchange
- AES-256-GCM encrypted message envelopes
- Server/client lifecycle events (`connect`, `ready`, `disconnect`, `error`)
- Secure room routing (`join`, `leave`, `to(room).emit`)
- Heartbeat-based zombie cleanup
- Auto-reconnect with exponential backoff
- **RPC-style ACK request/response with timeout support**

---

## Install

```bash
npm install @aegis-fluxion/core ws
```

---

## API at a Glance

### `SecureServer`

- `on("connection" | "ready" | "disconnect" | "error", handler)`
- `on("custom:event", (data, client) => unknown | Promise<unknown>)`
- `emit(event, data): SecureServer`
- `emitTo(clientId, event, data): boolean`
- `emitTo(clientId, event, data, callback): boolean`
- `emitTo(clientId, event, data, options): Promise<unknown>`
- `emitTo(clientId, event, data, options, callback): boolean`
- `to(room).emit(event, data): SecureServer`
- `close(code?, reason?): void`

### `SecureServerClient`

- `id: string`
- `socket: WebSocket`
- `join(room): boolean`
- `leave(room): boolean`
- `leaveAll(): number`
- `emit(event, data, ...ackArgs): boolean | Promise<unknown>`

### `SecureClient`

- `connect(): void`
- `disconnect(code?, reason?): void`
- `isConnected(): boolean`
- `readyState: number | null`
- `emit(event, data): boolean`
- `emit(event, data, callback): boolean`
- `emit(event, data, options): Promise<unknown>`
- `emit(event, data, options, callback): boolean`
- `on("connect" | "ready" | "disconnect" | "error", handler)`
- `on("custom:event", handler)`

---

## ACK (Request-Response) Usage

### 1) Client -> Server (Promise ACK)

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ port: 8080, host: "127.0.0.1" });

server.on("math:add", ({ a, b }) => {
  return { total: Number(a) + Number(b) };
});

const client = new SecureClient("ws://127.0.0.1:8080");

client.on("ready", async () => {
  const response = await client.emit(
    "math:add",
    { a: 2, b: 3 },
    { timeoutMs: 1000 }
  );

  console.log(response); // { total: 5 }
});
```

### 2) Client -> Server (Callback ACK)

```ts
client.emit(
  "math:add",
  { a: 4, b: 6 },
  { timeoutMs: 1000 },
  (error, response) => {
    if (error) {
      console.error("ACK error:", error.message);
      return;
    }

    console.log(response); // { total: 10 }
  }
);
```

### 3) Server -> Client (Promise ACK)

```ts
server.on("ready", async (clientSocket) => {
  const response = await clientSocket.emit(
    "agent:health",
    { verbose: true },
    { timeoutMs: 1200 }
  );

  console.log(response);
});

client.on("agent:health", () => {
  return { ok: true, uptime: process.uptime() };
});
```

### 4) ACK Timeout Behavior

When no response arrives before `timeoutMs`, ACK request fails:

- Promise form -> rejects with timeout error
- Callback form -> callback receives `Error`

```ts
try {
  await client.emit("never:respond", { ping: true }, { timeoutMs: 300 });
} catch (error) {
  console.error((error as Error).message);
  // ACK response timed out after 300ms for event "never:respond".
}
```

---

## Security Notes

- ACK request and ACK response frames are encrypted with the same AES-GCM tunnel as normal events.
- Internal handshake/RPC transport events are reserved and cannot be emitted manually.
- On disconnect/heartbeat timeout, pending ACK promises are rejected and memory state is cleaned.

---

## Development

From monorepo root:

```bash
npm run typecheck -w @aegis-fluxion/core
npm run test -w @aegis-fluxion/core
npm run build -w @aegis-fluxion/core
```

---

## Publish

From monorepo root:

```bash
npm publish -w @aegis-fluxion/core --access public
```

---

## License

MIT
