# @aegis-fluxion/core

Low-level encrypted WebSocket primitives for the `aegis-fluxion` ecosystem.

Version: **0.10.0**

---

## Highlights

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM encrypted envelopes
- Built-in telemetry via `getMetrics()` and `getMetricsPrometheus()`
- ACK request/response (Promise + callback styles)
- Encrypted chunked streaming for large `Buffer`/`Readable` payloads
- Secure room routing (`join`, `leave`, `leaveAll`, `to(room).emit(...)`)
- Middleware phases: `connection`, `incoming`, `outgoing`
- Rate limiting and DDoS controls per connection and IP
- TLS 1.3-style session resumption with encrypted one-time tickets
- **Horizontal scaling hooks** via pluggable `SecureServerAdapter`

---

## Install

```bash
npm install @aegis-fluxion/core ws
```

---

## Observability & telemetry (new in 0.10.0)

`SecureServer` exposes real-time metrics for operational visibility:

- active secure connections
- successful/failed handshakes (including resume attempts)
- encrypted message and byte throughput (ingress/egress)
- DDoS/rate-limit counters (blocked, throttled, disconnected)

### JSON metrics snapshot

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

const snapshot = server.getMetrics();
console.log(snapshot.activeConnections);
console.log(snapshot.encryptedMessagesReceivedTotal);
```

### Prometheus endpoint integration

```ts
import { createServer } from "node:http";
import { SecureServer } from "@aegis-fluxion/core";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 8080 });

createServer((request, response) => {
  if (request.url === "/metrics") {
    response.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    response.end(secureServer.getMetricsPrometheus());
    return;
  }

  response.statusCode = 404;
  response.end("Not Found");
}).listen(9100, "127.0.0.1");
```

---

## Frontend integration (React)

`@aegis-fluxion/core` is server/runtime focused. For browser clients, pair it with
`@aegis-fluxion/browser-client`.

### Node backend (`SecureServer`)

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.on("feed:publish", async (payload) => {
  server.emit("feed:message", payload);
  return { ok: true };
});
```

### React frontend (`BrowserSecureClient`)

```tsx
import { useEffect, useMemo, useState } from "react";
import { BrowserSecureClient } from "@aegis-fluxion/browser-client";

export function SecureFeedPanel() {
  const [status, setStatus] = useState("connecting");
  const [messages, setMessages] = useState<string[]>([]);

  const client = useMemo(() => {
    return new BrowserSecureClient("ws://127.0.0.1:8080", {
      autoConnect: false,
      reconnect: true
    });
  }, []);

  useEffect(() => {
    const onReady = () => setStatus("ready");
    const onDisconnect = () => setStatus("disconnected");
    const onFeedMessage = (payload: unknown) => {
      const data = payload as { text?: string };
      if (typeof data.text === "string") {
        setMessages((prev) => [data.text, ...prev]);
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
      <p>Status: {status}</p>
      <ul>
        {messages.map((message) => (
          <li key={message}>{message}</li>
        ))}
      </ul>
    </section>
  );
}
```

---

## Chunked streaming (new in 0.9.0)

`@aegis-fluxion/core@0.9.0` adds secure chunked stream transport for large payloads.

### Supported stream sources

- `Buffer`
- `Uint8Array`
- `Readable`
- `AsyncIterable<Buffer | Uint8Array | ArrayBuffer>`

### Stream APIs

- Client outbound: `client.emitStream(event, source, options?)`
- Client inbound: `client.onStream(event, handler)`
- Server outbound: `server.emitStreamTo(clientId, event, source, options?)`
- Server inbound: `server.onStream(event, handler)`
- Per-client server outbound helper: `serverClient.emitStream(event, source, options?)`

### Options

- `chunkSizeBytes` (default `64 * 1024`, max `1024 * 1024`)
- `metadata` (optional object attached to the stream start frame)
- `totalBytes` (optional size hint; required when source size is unknown and you want announced size)
- `signal` (`AbortSignal` to cancel transfer)

### Example

```ts
import { Readable } from "node:stream";
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });
const client = new SecureClient("ws://127.0.0.1:8080");

server.onStream("media:upload", async (stream, info, peer) => {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const uploaded = Buffer.concat(chunks);

  await peer.emitStream("media:download", Readable.from(uploaded), {
    chunkSizeBytes: 64 * 1024,
    totalBytes: uploaded.length,
    metadata: { direction: "server-to-client" }
  });

  console.log("Server received stream", {
    streamId: info.streamId,
    announcedTotalBytes: info.totalBytes,
    receivedBytes: uploaded.length
  });
});

client.on("ready", async () => {
  const payload = Buffer.from("chunked secure payload");

  const result = await client.emitStream("media:upload", payload, {
    chunkSizeBytes: 64 * 1024,
    totalBytes: payload.length,
    metadata: { direction: "client-to-server" }
  });

  console.log(result); // { streamId, chunkCount, totalBytes }
});
```

Each chunk is delivered inside reserved internal `start/chunk/end/abort` frames and encrypted
through the same AES-256-GCM channel used by standard events.

---

## Session resumption (TLS 1.3-style)

`@aegis-fluxion/core@0.8.0` introduced secure resume-first reconnect behavior:

- Full handshake path uses ephemeral ECDH (`hello` frame).
- Resume path uses ticket-bound proofs (`resume` / `resume-ack` frames).
- Successful resumes derive fresh channel keys from ticket secret + client nonce.
- Servers enforce ticket TTL, bounded cache size, and one-time ticket consumption.
- Clients automatically fall back to full handshake when resume is rejected.

### Server configuration

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  sessionResumption: {
    enabled: true,
    ticketTtlMs: 60_000,
    maxCachedTickets: 10_000
  }
});
```

### Client configuration

```ts
import { SecureClient } from "@aegis-fluxion/core";

const client = new SecureClient("ws://127.0.0.1:8080", {
  reconnect: true,
  sessionResumption: {
    enabled: true,
    maxAcceptedTicketTtlMs: 60_000
  }
});
```

### Security model

- Resume proofs are validated with HMAC and constant-time comparison.
- Resume tickets are encrypted in transit (same channel protections as all payloads).
- Resume tickets are discarded if expired, policy-invalid, or already consumed.
- Reserved internal events (e.g., session-ticket transport) cannot be emitted by user code.

---

## SecureServer adapter API (horizontal scaling)

### Core types

```ts
export interface SecureServerAdapterMessage {
  version: 1;
  originServerId: string;
  scope: "broadcast" | "room";
  event: string;
  data: unknown;
  emittedAt: number;
  room?: string;
}

export interface SecureServerAdapter {
  attach(server: SecureServer): void | Promise<void>;
  publish(message: SecureServerAdapterMessage): void | Promise<void>;
  detach?(server: SecureServer): void | Promise<void>;
}
```

### SecureServer hooks

- constructor option: `new SecureServer({ ..., adapter })`
- runtime binding: `await server.setAdapter(adapter)`
- inbound relay: `await server.handleAdapterMessage(message)`
- instance identity: `server.serverId`

### Message normalization helper

```ts
import { normalizeSecureServerAdapterMessage } from "@aegis-fluxion/core";
```

Use it in adapters before delivering inbound Pub/Sub payloads to `SecureServer`.

---

## Adapter integration example

```ts
import {
  SecureServer,
  type SecureServerAdapter,
  type SecureServerAdapterMessage
} from "@aegis-fluxion/core";

class InMemoryAdapter implements SecureServerAdapter {
  private static readonly peers = new Set<InMemoryAdapter>();
  private server: SecureServer | null = null;

  async attach(server: SecureServer): Promise<void> {
    this.server = server;
    InMemoryAdapter.peers.add(this);
  }

  async publish(message: SecureServerAdapterMessage): Promise<void> {
    for (const peer of InMemoryAdapter.peers) {
      if (peer === this || !peer.server) {
        continue;
      }

      await peer.server.handleAdapterMessage(message);
    }
  }

  async detach(server: SecureServer): Promise<void> {
    if (this.server !== server) {
      return;
    }

    this.server = null;
    InMemoryAdapter.peers.delete(this);
  }
}

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  adapter: new InMemoryAdapter()
});
```

---

## Middleware and ACK example

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.use(async (context, next) => {
  if (context.phase === "connection") {
    context.metadata.set("auth.role", "operator");
  }

  await next();
});

server.on("jobs:create", async (payload, client) => {
  return {
    ok: true,
    role: client.metadata.get("auth.role"),
    payload
  };
});

const client = new SecureClient("ws://127.0.0.1:8080");

client.on("ready", async () => {
  const response = await client.emit("jobs:create", { id: "job-42" }, { timeoutMs: 1200 });
  console.log(response);
});
```

---

## Rate limiting and DDoS shield

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  rateLimit: {
    enabled: true,
    windowMs: 1_000,
    maxEventsPerConnection: 120,
    maxEventsPerIp: 300,
    action: "throttle", // or "disconnect"
    throttleMs: 150,
    maxThrottleMs: 2_000,
    disconnectAfterViolations: 4,
    disconnectCode: 1013,
    disconnectReason: "Rate limit exceeded. Please retry later."
  }
});
```

---

## Binary payload support

Supported encrypted payload types:

- `Buffer`
- `Uint8Array`
- `Blob`

Binary fields can be nested in standard JSON objects and arrays.

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
