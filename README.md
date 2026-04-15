# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.7.3-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is an end-to-end encrypted WebSocket toolkit for Node.js and TypeScript.

It provides secure event transport with ephemeral ECDH key exchange, AES-256-GCM envelopes,
TLS 1.3-style session resumption, ACK request/response semantics, binary payload support,
middleware-based policy controls, and horizontal scaling through Redis Pub/Sub adapters.

---

## Packages

| Package | Purpose |
| --- | --- |
| `aegis-fluxion` | Umbrella package (recommended app-facing import) |
| `@aegis-fluxion/core` | Secure transport primitives (`SecureServer`, `SecureClient`) |
| `@aegis-fluxion/mcp-adapter` | MCP JSON-RPC transport over encrypted channels |
| `@aegis-fluxion/redis-adapter` | Horizontal scaling adapter for cluster fanout |

---

## What's new in 0.7.3

- Added TLS 1.3-style **session resumption** to secure reconnect flows.
- Clients can attempt resume-first handshakes and automatically fall back to full ECDH.
- Servers now issue encrypted one-time session tickets with configurable TTL and cache limits.
- Umbrella package now targets `@aegis-fluxion/core@^0.8.0`.

---

## Install

```bash
npm install aegis-fluxion ws redis
```

---

## Quick start

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

server.on("notes:create", async (payload, client) => {
  return {
    ok: true,
    tenant: client.metadata.get("tenant"),
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
    { note: "hello secure world" },
    { timeoutMs: 1500 }
  );

  console.log(result);
});
```

---

## Session resumption example

```ts
import { SecureClient, SecureServer } from "aegis-fluxion";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  sessionResumption: {
    enabled: true,
    ticketTtlMs: 60_000,
    maxCachedTickets: 2_048
  }
});

const client = new SecureClient("ws://127.0.0.1:8080", {
  reconnect: true,
  sessionResumption: {
    enabled: true,
    maxAcceptedTicketTtlMs: 60_000
  }
});

client.on("ready", () => {
  console.log("Secure channel ready (full handshake or resumed handshake).");
});
```

When a valid ticket is cached, reconnects can skip extra ECDH secret recomputation and
resume directly with authenticated resume proofs.

---

## Horizontal scaling with Redis

```ts
import {
  RedisSecureServerAdapter,
  SecureServer
} from "aegis-fluxion";

const redisUrl = "redis://127.0.0.1:6379";
const channel = "aegis-fluxion:cluster:prod";

const serverA = new SecureServer({
  host: "127.0.0.1",
  port: 8081,
  adapter: new RedisSecureServerAdapter({ redisUrl, channel })
});

const serverB = new SecureServer({
  host: "127.0.0.1",
  port: 8082,
  adapter: new RedisSecureServerAdapter({ redisUrl, channel })
});

serverA.on("connection", (client) => client.join("ops"));
serverB.on("connection", (client) => client.join("ops"));

// Reaches room subscribers on BOTH instances.
serverA.to("ops").emit("ops:alert", {
  from: "server-a",
  message: "Cluster-wide event"
});
```

---

## Security and reliability capabilities

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM authenticated encryption for all application payloads
- Binary payload support (`Buffer`, `Uint8Array`, `Blob`)
- TLS 1.3-style session resumption with encrypted one-time tickets
- ACK request/response with timeout controls
- Rate limiting and DDoS controls (per connection + per IP)
- Heartbeat zombie cleanup and reconnect backoff handling

---

## MCP transport

`aegis-fluxion` also re-exports MCP transport helpers:

```ts
import { SecureMCPTransport } from "aegis-fluxion";
```

See package docs: [`packages/mcp-adapter/README.md`](./packages/mcp-adapter/README.md)

---

## Development

From repository root:

```bash
npm install
npm run typecheck
npm run test
npm run build
```

---

## Changelog

Full release history is documented in [`CHANGELOG.md`](./CHANGELOG.md).

---

## License

MIT
