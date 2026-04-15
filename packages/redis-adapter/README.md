# @aegis-fluxion/redis-adapter

Redis Pub/Sub adapter for horizontal scaling of `SecureServer` instances.

Version: **0.1.0**

---

## What it does

`RedisSecureServerAdapter` synchronizes encrypted event fanout across multiple Node.js processes/instances:

- **Broadcast replication** (`server.emit(...)`)
- **Room replication** (`server.to(room).emit(...)`)

This enables horizontal scaling while keeping your existing `@aegis-fluxion/core` application event model.

---

## Install

```bash
npm install @aegis-fluxion/redis-adapter @aegis-fluxion/core redis ws
```

---

## Quick Start

```ts
import { SecureServer } from "@aegis-fluxion/core";
import { RedisSecureServerAdapter } from "@aegis-fluxion/redis-adapter";

const adapter = new RedisSecureServerAdapter({
  redisUrl: "redis://127.0.0.1:6379",
  channel: "aegis-fluxion:cluster:v1"
});

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  adapter
});

server.on("connection", (client) => {
  client.join("ops");
});

server.on("ops:ping", (payload) => {
  console.log("Received:", payload);
});

// Replicated to all instances + local clients.
server.emit("cluster:announcement", { from: "instance-a" });

// Replicated to room members across all instances.
server.to("ops").emit("ops:ping", { from: "instance-a" });
```

---

## Two-instance topology example

```ts
import { SecureServer } from "@aegis-fluxion/core";
import { RedisSecureServerAdapter } from "@aegis-fluxion/redis-adapter";

const sharedRedisUrl = "redis://127.0.0.1:6379";
const sharedChannel = "aegis-fluxion:cluster:prod";

const adapterA = new RedisSecureServerAdapter({
  redisUrl: sharedRedisUrl,
  channel: sharedChannel
});

const adapterB = new RedisSecureServerAdapter({
  redisUrl: sharedRedisUrl,
  channel: sharedChannel
});

const serverA = new SecureServer({ host: "127.0.0.1", port: 8081, adapter: adapterA });
const serverB = new SecureServer({ host: "127.0.0.1", port: 8082, adapter: adapterB });

serverA.on("connection", (client) => client.join("alerts"));
serverB.on("connection", (client) => client.join("alerts"));

serverA.to("alerts").emit("alerts:new", {
  level: "info",
  source: "server-a"
});
```

---

## API

### `RedisSecureServerAdapter(options?)`

```ts
new RedisSecureServerAdapter({
  redisUrl?: string;
  channel?: string;
  publisher?: RedisClientType;
  subscriber?: RedisClientType;
  onError?: (error: Error) => void;
});
```

- `redisUrl`: Redis connection URL (default Redis client behavior if omitted)
- `channel`: Pub/Sub channel name (default internal cluster channel)
- `publisher` / `subscriber`: Optional prebuilt Redis clients for custom lifecycle control
- `onError`: Optional adapter-level error hook

### Lifecycle methods

- `attach(server)` — binds adapter to one `SecureServer`
- `publish(message)` — publishes normalized replication payload
- `detach(server)` — unsubscribes and closes owned clients

---

## Operational notes

- Attach one adapter instance to one `SecureServer`.
- Use a shared Redis channel across all instances participating in one cluster.
- Keep Redis ACL/auth and network policies strict in production.
- `originServerId` filtering prevents same-node replay loops.

---

## Development

From repository root:

```bash
npm run typecheck -w @aegis-fluxion/redis-adapter
npm run test -w @aegis-fluxion/redis-adapter
npm run build -w @aegis-fluxion/redis-adapter
```

---

## License

MIT
