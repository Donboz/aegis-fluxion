# aegis-fluxion

Main end-user package for the `aegis-fluxion` secure messaging toolkit.

This package re-exports the full public API from `@aegis-fluxion/core`, including
`SecureServer`, `SecureClient`, and all related types.

Version: **0.7.0**

---

## Installation

```bash
npm install aegis-fluxion ws
```

---

## Why `aegis-fluxion`

- ECDH + AES-256-GCM encrypted transport
- Encrypted ACK request/response with timeout control
- Room-based secure fanout
- Heartbeat cleanup + reconnect resilience
- **Binary support out of the box** (`Buffer`, `Uint8Array`, `Blob`)
- **Middleware auth and policy hooks** (`connection` / `incoming` / `outgoing`)
- Per-client metadata pipeline via `client.metadata`
- **MCP transport adapter** (`SecureMCPTransport`) for JSON-RPC over encrypted WebSocket

---

## Quick Start (Middleware + ACK)

```ts
import { SecureClient, SecureServer } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.use(async (context, next) => {
  if (context.phase === "connection") {
    const rawApiKey = context.request.headers["x-api-key"];
    const apiKey = Array.isArray(rawApiKey) ? rawApiKey[0] : rawApiKey;

    if (apiKey !== "dev-secret") {
      throw new Error("Unauthorized");
    }

    context.metadata.set("tenant", "acme");
  }

  await next();
});

server.use(async (context, next) => {
  if (
    context.phase === "incoming" &&
    context.event === "file:upload" &&
    typeof context.data === "object" &&
    context.data !== null
  ) {
    const payload = context.data as { name?: string; chunk?: Uint8Array; previewBlob?: Blob };
    context.data = {
      name: String(payload.name ?? "").trim(),
      chunk: payload.chunk,
      previewBlob: payload.previewBlob
    };
  }

  await next();
});

server.on("file:upload", async (payload) => {
  const { name, chunk, previewBlob } = payload as { name: string; chunk: Uint8Array; previewBlob: Blob };

  return {
    name,
    chunkBytes: chunk.byteLength,
    previewBytes: previewBlob.size,
    accepted: true
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
  const response = await client.emit(
    "file:upload",
    {
      name: "avatar.png",
      chunk: Uint8Array.from([137, 80, 78, 71]),
      previewBlob: new Blob([Buffer.from("tiny-preview")], {
        type: "image/png"
      })
    },
    { timeoutMs: 2000 }
  );

  console.log(response);
});
```

---

## Middleware Notes

- `connection` middleware runs before the app accepts the socket.
- Unauthorized sockets are closed with policy code `1008`.
- `incoming` and `outgoing` middleware can transform event names/payloads.
- Metadata set during middleware is available later through `client.metadata`.

---

## Callback-style ACK Example

```ts
client.emit(
  "file:upload",
  {
    name: "report.bin",
    chunk: Buffer.from("01020304", "hex"),
    previewBlob: new Blob([Buffer.from("ok")], {
      type: "application/octet-stream"
    })
  },
  { timeoutMs: 2000 },
  (error, response) => {
    if (error) {
      console.error(error.message);
      return;
    }

    console.log(response);
  }
);
```

---

## MCP Adapter Quick Start

`aegis-fluxion` re-exports `SecureMCPTransport`, so you can wire MCP-compatible traffic
directly without importing separate packages.

```ts
import {
  SecureClient,
  SecureMCPTransport,
  SecureServer,
  type SecureMCPMessage
} from "aegis-fluxion";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 9092 });

secureServer.on("connection", async (client) => {
  const transport = new SecureMCPTransport({
    mode: "server",
    server: secureServer,
    clientId: client.id
  });

  transport.onmessage = async (message: SecureMCPMessage) => {
    console.log("Server MCP message", message);
  };

  await transport.start();
});

const secureClient = new SecureClient("ws://127.0.0.1:9092");

const transport = new SecureMCPTransport({
  mode: "client",
  client: secureClient
});

await transport.start();
await transport.send({
  jsonrpc: "2.0",
  id: 1,
  method: "resources/list",
  params: {}
});
```

---

## Binary Payload Notes

- Binary integrity is protected by AES-GCM authentication tags.
- Payload type is preserved across encrypted transport.
- Mixed payloads (JSON + binary) are supported.

---

## Related Docs

- Core package docs: [`../core/README.md`](../core/README.md)
- MCP adapter docs: [`../mcp-adapter/README.md`](../mcp-adapter/README.md)
- Repository changelog: [`../../CHANGELOG.md`](../../CHANGELOG.md)

---

## License

MIT
