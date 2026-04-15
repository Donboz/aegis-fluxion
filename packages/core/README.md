# @aegis-fluxion/core

Low-level E2E-encrypted WebSocket primitives for the `aegis-fluxion` ecosystem.

If you prefer a single user-facing package, use [`aegis-fluxion`](../aegis-fluxion/README.md).

Version: **0.5.0**

---

## Highlights

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM encrypted envelopes
- Encrypted ACK request/response (`Promise` and callback)
- Secure room routing (`join`, `leave`, `leaveAll`, `to(room).emit`)
- Heartbeat and zombie socket cleanup
- Auto-reconnect with fresh re-handshake
- **Binary payload support**: `Buffer`, `Uint8Array`, `Blob`

---

## Install

```bash
npm install @aegis-fluxion/core ws
```

---

## Binary Data Support

`@aegis-fluxion/core` supports encrypted binary payload transfer while preserving type fidelity.

Supported send/receive types:

- `Buffer`
- `Uint8Array`
- `Blob`

Binary values can be nested in regular objects and arrays.

---

## Example: Encrypted Binary Event

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });
const client = new SecureClient("ws://127.0.0.1:8080");

server.on("image:chunk", (data, socket) => {
  const chunk = data as Buffer;

  if (!Buffer.isBuffer(chunk)) {
    throw new Error("Expected Buffer payload.");
  }

  socket.emit("image:chunk:ack", chunk);
});

client.on("ready", () => {
  const imageChunk = Buffer.from("89504e470d0a", "hex");
  client.emit("image:chunk", imageChunk);
});

client.on("image:chunk:ack", (payload) => {
  const echoedChunk = payload as Buffer;
  console.log("Echoed bytes:", echoedChunk.byteLength);
});
```

---

## Example: ACK Roundtrip with Mixed Binary Types

```ts
server.on("binary:inspect", async (payload) => {
  const { file, bytes, blob } = payload as {
    file: Buffer;
    bytes: Uint8Array;
    blob: Blob;
  };

  return {
    fileBytes: file.byteLength,
    bytesBytes: bytes.byteLength,
    blobBytes: blob.size
  };
});

client.on("ready", async () => {
  const result = await client.emit(
    "binary:inspect",
    {
      file: Buffer.from("file-binary"),
      bytes: Uint8Array.from([1, 2, 3, 4]),
      blob: new Blob([Buffer.from("blob-binary")], {
        type: "application/octet-stream"
      })
    },
    { timeoutMs: 1500 }
  );

  console.log(result);
});
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

## Security Notes

- All payloads (including binary) are encrypted end-to-end with AES-256-GCM.
- Authentication tags are verified on every packet (tampered packets are dropped).
- Internal transport events are reserved (`__handshake`, `__rpc:req`, `__rpc:res`).
- Pending ACK requests are rejected on timeout/disconnect.

---

## Development

From repository root:

```bash
npm run typecheck -w @aegis-fluxion/core
npm run test -w @aegis-fluxion/core
npm run build -w @aegis-fluxion/core
```

---

## License

MIT
