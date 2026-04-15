# @aegis-fluxion/core

Low-level E2E-encrypted WebSocket primitives for the `aegis-fluxion` ecosystem.

If you prefer a single user-facing package, use [`aegis-fluxion`](../aegis-fluxion/README.md).

Version: **0.7.0**

---

## Highlights

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM encrypted envelopes
- Encrypted ACK request/response (`Promise` and callback)
- Secure room routing (`join`, `leave`, `leaveAll`, `to(room).emit`)
- Heartbeat and zombie socket cleanup
- Auto-reconnect with fresh re-handshake
- **Binary payload support**: `Buffer`, `Uint8Array`, `Blob`
- **Server middleware pipeline** via `SecureServer.use(...)`
- Middleware phases: `connection`, `incoming`, `outgoing`
- Per-socket middleware metadata available as `SecureServerClient.metadata`
- Optional MCP bridge package: `@aegis-fluxion/mcp-adapter`

---

## Install

```bash
npm install @aegis-fluxion/core ws
```

---

## Middleware in 0.6.0+

`SecureServer` now supports phase-based middleware for auth, policy enforcement, and payload
normalization.

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.use(async (context, next) => {
  if (context.phase === "connection") {
    const rawApiKey = context.request.headers["x-api-key"];
    const apiKey = Array.isArray(rawApiKey) ? rawApiKey[0] : rawApiKey;

    if (apiKey !== "dev-secret") {
      throw new Error("Unauthorized");
    }

    context.metadata.set("role", "editor");
  }

  await next();
});

server.use(async (context, next) => {
  if (
    context.phase === "incoming" &&
    context.event === "post:create" &&
    typeof context.data === "object" &&
    context.data !== null
  ) {
    const payload = context.data as { title?: string };
    context.data = { title: String(payload.title ?? "").trim() };
  }

  await next();

  if (context.phase === "outgoing" && context.event === "post:create") {
    context.data = {
      ...(context.data as Record<string, unknown>),
      middleware: true
    };
  }
});

server.on("post:create", async (payload, client) => {
  return {
    ok: true,
    role: client.metadata.get("role"),
    payload
  };
});

const client = new SecureClient("ws://127.0.0.1:8080", {
  wsOptions: {
    headers: {
      "x-api-key": "dev-secret"
    }
  }
});

client.on("ready", async () => {
  const response = await client.emit("post:create", { title: "  Hello  " }, { timeoutMs: 1500 });
  console.log(response);
});
```

Notes:

- Throwing in `connection` middleware rejects the socket and closes with code `1008`.
- `metadata` is mutable in middleware (`Map`) and exposed read-only on `SecureServerClient`.

---

## MCP Adapter Integration (0.7.0)

Use `@aegis-fluxion/mcp-adapter` to carry MCP JSON-RPC messages through your encrypted core
transport.

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";
import { SecureMCPTransport } from "@aegis-fluxion/mcp-adapter";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 9091 });

secureServer.on("connection", async (client) => {
  const mcpServerTransport = new SecureMCPTransport({
    mode: "server",
    server: secureServer,
    clientId: client.id
  });

  mcpServerTransport.onmessage = async (message) => {
    // Forward into your MCP server runtime.
    console.log("MCP request on server tunnel", message);
  };

  await mcpServerTransport.start();
});

const secureClient = new SecureClient("ws://127.0.0.1:9091");

const mcpClientTransport = new SecureMCPTransport({
  mode: "client",
  client: secureClient
});

await mcpClientTransport.start();

await mcpClientTransport.send({
  jsonrpc: "2.0",
  id: 100,
  method: "tools/list",
  params: {}
});
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
- `use((context, next) => void | Promise<void>)`
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
- `metadata: ReadonlyMap<string, unknown>`
- `emit(event, data, ...ackArgs): boolean | Promise<unknown>`
- `join(room): boolean`
- `leave(room): boolean`
- `leaveAll(): number`

### Middleware Types

- `SecureServerMiddleware`
- `SecureServerMiddlewareContext`
- `SecureServerConnectionMiddlewareContext`
- `SecureServerMessageMiddlewareContext`
- `SecureServerMiddlewareNext`

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
- Middleware-level policy rejection uses WebSocket close code `1008`.

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
