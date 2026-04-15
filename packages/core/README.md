# @aegis-fluxion/core

Low-level E2E-encrypted WebSocket primitives for the `aegis-fluxion` ecosystem.

If you want a single user-facing package, use [`aegis-fluxion`](../aegis-fluxion/README.md).

Version: **0.4.0**

---

## Features

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM encrypted application envelopes
- Server/client lifecycle hooks (`connect`, `ready`, `disconnect`, `error`)
- Secure room routing (`join`, `leave`, `leaveAll`, `to(room).emit`)
- Heartbeat Ping/Pong zombie cleanup
- Client auto-reconnect with exponential backoff
- Encrypted RPC-style ACK request/response (Promise and callback)

---

## Install

```bash
npm install @aegis-fluxion/core ws
```

---

## API Snapshot

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
- `emit(event, data, ...ackArgs): boolean | Promise<unknown>`
- `join(room): boolean`
- `leave(room): boolean`
- `leaveAll(): number`

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

## ACK Request/Response Examples

### Client -> Server (Promise)

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

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

### Client -> Server (Callback)

```ts
client.emit(
  "math:add",
  { a: 4, b: 6 },
  { timeoutMs: 1000 },
  (error, response) => {
    if (error) {
      console.error(error.message);
      return;
    }

    console.log(response); // { total: 10 }
  }
);
```

### Server -> Client (Promise)

```ts
server.on("ready", async (clientSocket) => {
  const response = await clientSocket.emit(
    "agent:health",
    { verbose: true },
    { timeoutMs: 1200 }
  );

  console.log(response);
});
```

---

## Security Notes

- ACK requests and responses use the same encrypted AES-GCM channel.
- Internal handshake/RPC transport events are reserved.
- Pending ACK requests are rejected on timeout/disconnect.
- Tampered encrypted packets are dropped.

---

## Development

From repository root:

```bash
npm run typecheck -w @aegis-fluxion/core
npm run test -w @aegis-fluxion/core
npm run build -w @aegis-fluxion/core
```

---

## Publish

From repository root:

```bash
npm publish -w @aegis-fluxion/core --access public
```

---

## License

MIT
