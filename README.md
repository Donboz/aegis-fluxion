# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.7.0-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is an end-to-end encrypted WebSocket toolkit for Node.js and TypeScript.

It provides a secure event channel with ephemeral ECDH key exchange, AES-256-GCM encryption,
encrypted ACK request/response, native binary payload support for `Buffer`, `Uint8Array`, and
`Blob`, plus a phase-based middleware pipeline for connection policy, authentication, payload
transformation, and MCP (Model Context Protocol) transport adaptation.

---

## Packages

| Package | Purpose |
| --- | --- |
| `aegis-fluxion` | Main end-user package (recommended) |
| `@aegis-fluxion/core` | Low-level primitives and transport internals |
| `@aegis-fluxion/mcp-adapter` | MCP JSON-RPC transport over encrypted WebSocket tunnels |

---

## What's New in 0.7.0

- New `@aegis-fluxion/mcp-adapter` package
- `SecureMCPTransport` to carry MCP JSON-RPC traffic over encrypted channels
- Client and server transport modes for one secure MCP session per authenticated socket
- Umbrella package now re-exports MCP adapter APIs out of the box
- Existing middleware, binary, ACK, and reconnect features continue unchanged

---

## Install

```bash
npm install aegis-fluxion ws
```

---

## Quick Start (Middleware Auth + ACK)

```ts
import { SecureServer, SecureClient } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.use(async (context, next) => {
  if (context.phase === "connection") {
    const rawApiKey = context.request.headers["x-api-key"];
    const apiKey = Array.isArray(rawApiKey) ? rawApiKey[0] : rawApiKey;

    if (apiKey !== "dev-secret") {
      throw new Error("Unauthorized");
    }

    context.metadata.set("userId", "demo-user");
  }

  await next();
});

server.use(async (context, next) => {
  if (
    context.phase === "incoming" &&
    context.event === "notes:create" &&
    typeof context.data === "object" &&
    context.data !== null
  ) {
    const input = context.data as { note?: string };
    context.data = {
      note: String(input.note ?? "").trim()
    };
  }

  await next();

  if (context.phase === "outgoing" && context.event === "notes:create") {
    context.data = {
      ...(context.data as Record<string, unknown>),
      handledAt: new Date().toISOString()
    };
  }
});

server.on("notes:create", async (payload, client) => {
  const userId = client.metadata.get("userId");

  return {
    ok: true,
    userId,
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
  const result = await client.emit(
    "notes:create",
    { note: "  hello secure world  " },
    { timeoutMs: 2000 }
  );

  console.log(result);
});
```

---

## MCP Integration over Encrypted WebSocket Transport

`SecureMCPTransport` enables MCP-compatible JSON-RPC communication without stdio/SSE, fully
inside your encrypted `SecureClient`/`SecureServer` tunnel.

```ts
import {
  SecureClient,
  SecureMCPTransport,
  SecureServer,
  type SecureMCPMessage
} from "aegis-fluxion";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 9090 });

secureServer.use(async (context, next) => {
  if (context.phase === "connection") {
    const rawToken = context.request.headers.authorization;
    const token = Array.isArray(rawToken) ? rawToken[0] : rawToken;

    if (token !== "Bearer mcp-dev-token") {
      throw new Error("Unauthorized MCP peer");
    }
  }

  await next();
});

secureServer.on("connection", async (client) => {
  const serverTransport = new SecureMCPTransport({
    mode: "server",
    server: secureServer,
    clientId: client.id
  });

  serverTransport.onmessage = async (message: SecureMCPMessage) => {
    // Forward message to your MCP server runtime.
    console.log("Server-side MCP message:", message);
  };

  await serverTransport.start();
});

const secureClient = new SecureClient("ws://127.0.0.1:9090", {
  wsOptions: {
    headers: {
      authorization: "Bearer mcp-dev-token"
    }
  }
});

const clientTransport = new SecureMCPTransport({
  mode: "client",
  client: secureClient
});

clientTransport.onmessage = async (message: SecureMCPMessage) => {
  console.log("Client-side MCP message:", message);
};

await clientTransport.start();
await clientTransport.send({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/list",
  params: {}
});
```

---

## Middleware Execution Model

- `connection` phase runs before the connection is accepted by application handlers
- `incoming` phase runs before custom event handlers receive decrypted payloads
- `outgoing` phase runs before encrypted payloads are sent to client(s)
- Throwing in middleware rejects processing (for `connection`, the socket is closed with code `1008`)
- `metadata` is a mutable `Map<string, unknown>` in middleware and read-only in `SecureServerClient`

---

## Binary Payload Behavior

- `Buffer` arrives as `Buffer`
- `Uint8Array` arrives as `Uint8Array`
- `Blob` arrives as `Blob` (falls back to `Buffer` if `Blob` is unavailable in runtime)
- Binary values can be nested inside regular JSON objects/arrays

---

## Security Model

- Ephemeral ECDH (`prime256v1`) derives per-session secrets
- AES-256-GCM encrypts all application payloads (JSON and binary)
- GCM authentication tag enforces tamper detection and integrity
- Internal transport events are reserved and blocked from manual emit

---

## Reliability Features

- Heartbeat Ping/Pong stale-connection cleanup
- Client auto-reconnect with exponential backoff and jitter
- Fresh re-handshake and key derivation after reconnect
- Promise and callback ACK APIs with per-request timeouts

---

## Changelog

See [`CHANGELOG.md`](./CHANGELOG.md) for complete release history.

---

## Monorepo Development

From repository root:

```bash
npm install
npm run typecheck
npm run test
npm run build
```

---

## License

MIT
