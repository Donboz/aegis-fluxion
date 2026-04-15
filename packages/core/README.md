# @aegis-fluxion/core

Low-level encrypted WebSocket primitives for the `aegis-fluxion` ecosystem.

Version: **0.7.2**

---

## Highlights

- Ephemeral ECDH handshake (`prime256v1`)
- AES-256-GCM encrypted envelopes
- ACK request/response (Promise + callback styles)
- Secure room routing (`join`, `leave`, `leaveAll`, `to(room).emit(...)`)
- Middleware phases: `connection`, `incoming`, `outgoing`
- Rate limiting and DDoS controls per connection and IP
- **Horizontal scaling hooks** via pluggable `SecureServerAdapter`

---

## Install

```bash
npm install @aegis-fluxion/core ws
```

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
