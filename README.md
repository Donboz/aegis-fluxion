# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.7.6-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is an end-to-end encrypted WebSocket toolkit for Node.js and TypeScript.

It provides secure event transport with ephemeral ECDH key exchange, AES-256-GCM envelopes,
TLS 1.3-style session resumption, ACK request/response semantics, binary payload support,
chunked streaming for large payload transfers,
middleware-based policy controls, and horizontal scaling through Redis Pub/Sub adapters.

---

## Packages

| Package | Purpose |
| --- | --- |
| `aegis-fluxion` | Umbrella package (recommended app-facing import) |
| `@aegis-fluxion/core` | Secure transport primitives (`SecureServer`, `SecureClient`) |
| `@aegis-fluxion/browser-client` | Browser-native secure client (`Web Crypto` + native `WebSocket`) |
| `@aegis-fluxion/mcp-adapter` | MCP JSON-RPC transport over encrypted channels |
| `@aegis-fluxion/redis-adapter` | Horizontal scaling adapter for cluster fanout |

---

## What's new in 0.7.6

- Added Observability & Telemetry support in `@aegis-fluxion/core@0.10.0`.
- `SecureServer` now exposes:
  - `getMetrics()` for JSON metrics snapshots
  - `getMetricsPrometheus()` for Prometheus/OpenMetrics scraping
- Telemetry includes active connections, handshake success/failure,
  encrypted traffic counters, and blocked DDoS/rate-limit events.
- Umbrella package `aegis-fluxion@0.7.6` now depends on `@aegis-fluxion/core@^0.10.0`.

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

## Browser/Frontend SDK (React)

```tsx
import { useEffect, useMemo, useState } from "react";
import { BrowserSecureClient } from "@aegis-fluxion/browser-client";

export function SecureFeed() {
  const [status, setStatus] = useState("connecting");
  const [events, setEvents] = useState<string[]>([]);

  const client = useMemo(() => {
    return new BrowserSecureClient("wss://api.example.com/socket", {
      autoConnect: false,
      reconnect: true
    });
  }, []);

  useEffect(() => {
    const onReady = () => setStatus("ready");
    const onDisconnect = () => setStatus("disconnected");
    const onFeedMessage = (payload: unknown) => {
      const data = payload as { message?: string };
      if (typeof data.message === "string") {
        setEvents((prev) => [data.message, ...prev]);
      }
    };

    client.on("ready", onReady);
    client.on("disconnect", onDisconnect);
    client.on("feed:message", onFeedMessage);
    client.connect();

    return () => {
      client.off("ready", onReady);
      client.off("disconnect", onDisconnect);
      client.off("feed:message", onFeedMessage);
      client.disconnect();
    };
  }, [client]);

  return (
    <section>
      <p>Secure channel: {status}</p>
      <ul>
        {events.map((value) => (
          <li key={value}>{value}</li>
        ))}
      </ul>
    </section>
  );
}
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

## Chunked streaming example

```ts
import { SecureClient, SecureServer } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });
const client = new SecureClient("ws://127.0.0.1:8080");

server.onStream("files:upload", async (stream, info, peer) => {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const uploaded = Buffer.concat(chunks);

  // Stream back to the same peer (for example, checksum response or transformed file)
  await peer.emitStream("files:download", uploaded, {
    chunkSizeBytes: 64 * 1024,
    metadata: { source: "server" }
  });

  console.log("Upload complete", {
    streamId: info.streamId,
    totalBytes: uploaded.length
  });
});

client.on("ready", async () => {
  const payload = Buffer.from("large binary payload here");

  const result = await client.emitStream("files:upload", payload, {
    chunkSizeBytes: 64 * 1024,
    metadata: { source: "client" },
    totalBytes: payload.length
  });

  console.log(result); // { streamId, chunkCount, totalBytes }
});

client.onStream("files:download", async (stream, info) => {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  console.log("Download complete", {
    streamId: info.streamId,
    announcedTotalBytes: info.totalBytes,
    receivedBytes: Buffer.concat(chunks).length
  });
});
```

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

## Observability & telemetry

`SecureServer` now provides built-in runtime metrics you can consume directly or expose
for Prometheus scraping.

```ts
import { createServer } from "node:http";
import { SecureServer } from "aegis-fluxion";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 8080 });

const telemetryServer = createServer((request, response) => {
  if (!request.url) {
    response.statusCode = 400;
    response.end("Missing URL");
    return;
  }

  if (request.url === "/metrics") {
    response.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    response.end(secureServer.getMetricsPrometheus());
    return;
  }

  if (request.url === "/metrics.json") {
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    response.end(JSON.stringify(secureServer.getMetrics(), null, 2));
    return;
  }

  response.statusCode = 404;
  response.end("Not Found");
});

telemetryServer.listen(9100, "127.0.0.1");
```

---

## Security and reliability capabilities

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM authenticated encryption for all application payloads
- Binary payload support (`Buffer`, `Uint8Array`, `Blob`)
- Encrypted chunked streaming (`Buffer`, `Uint8Array`, `Readable`, `AsyncIterable`)
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
