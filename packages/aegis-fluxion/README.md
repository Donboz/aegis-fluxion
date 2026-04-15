# aegis-fluxion

Main end-user package for the `aegis-fluxion` secure messaging ecosystem.

Version: **0.7.3**

---

## Re-exported modules

`aegis-fluxion` re-exports all public APIs from:

- `@aegis-fluxion/core`
- `@aegis-fluxion/mcp-adapter`
- `@aegis-fluxion/redis-adapter`

This means you can build encrypted transport, MCP bridges, and Redis-based horizontal scaling
without multiple package-level imports.

---

## What's new in 0.7.3

- Umbrella package now targets `@aegis-fluxion/core@^0.8.0`.
- Session resumption is now available through `SecureServer` and `SecureClient` exports.
- Resume-first reconnects can reuse secure session tickets and fall back safely to full handshake.

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

server.on("tasks:create", async (payload) => {
  return {
    ok: true,
    payload
  };
});

const client = new SecureClient("ws://127.0.0.1:8080");

client.on("ready", async () => {
  const response = await client.emit("tasks:create", { id: "t-1" }, { timeoutMs: 1200 });
  console.log(response);
});
```

---

## Session resumption quick example

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
  console.log("Secure channel is ready (resumed or full handshake).");
});
```

---

## Horizontal scaling example (Redis adapter)

```ts
import {
  RedisSecureServerAdapter,
  SecureServer
} from "aegis-fluxion";

const redisUrl = "redis://127.0.0.1:6379";
const channel = "aegis-fluxion:cluster:prod";

const adapterA = new RedisSecureServerAdapter({ redisUrl, channel });
const adapterB = new RedisSecureServerAdapter({ redisUrl, channel });

const serverA = new SecureServer({
  host: "127.0.0.1",
  port: 8081,
  adapter: adapterA
});

const serverB = new SecureServer({
  host: "127.0.0.1",
  port: 8082,
  adapter: adapterB
});

serverA.on("connection", (client) => client.join("alerts"));
serverB.on("connection", (client) => client.join("alerts"));

serverA.to("alerts").emit("alerts:new", {
  level: "info",
  source: "server-a"
});
```

---

## MCP transport example

```ts
import {
  SecureClient,
  SecureMCPTransport,
  SecureServer,
  type SecureMCPMessage
} from "aegis-fluxion";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 9092 });

secureServer.on("connection", async (client) => {
  const serverTransport = new SecureMCPTransport({
    mode: "server",
    server: secureServer,
    clientId: client.id
  });

  serverTransport.onmessage = async (message: SecureMCPMessage) => {
    console.log("Server MCP message", message);
  };

  await serverTransport.start();
});

const secureClient = new SecureClient("ws://127.0.0.1:9092");

const clientTransport = new SecureMCPTransport({
  mode: "client",
  client: secureClient
});

await clientTransport.start();
await clientTransport.send({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/list",
  params: {}
});
```

---

## Related documentation

- Core: [`../core/README.md`](../core/README.md)
- Redis adapter: [`../redis-adapter/README.md`](../redis-adapter/README.md)
- MCP adapter: [`../mcp-adapter/README.md`](../mcp-adapter/README.md)
- Changelog: [`../../CHANGELOG.md`](../../CHANGELOG.md)

---

## License

MIT
