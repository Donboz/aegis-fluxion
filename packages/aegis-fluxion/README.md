# aegis-fluxion

Main end-user package for the `aegis-fluxion` secure messaging ecosystem.

Version: **0.7.5**

---

## Re-exported modules

`aegis-fluxion` re-exports all public APIs from:

- `@aegis-fluxion/core`
- `@aegis-fluxion/browser-client`
- `@aegis-fluxion/mcp-adapter`
- `@aegis-fluxion/redis-adapter`

This means you can build encrypted transport, MCP bridges, and Redis-based horizontal scaling
without multiple package-level imports.

---

## What's new in 0.7.5

- New frontend/browser package support through `@aegis-fluxion/browser-client@^0.1.0`.
- Browser client APIs are now available from umbrella exports.
- Existing secure transport features (ACK, binary payloads, chunked streaming) remain available.

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

## Frontend React quick example

```tsx
import { useEffect, useMemo, useState } from "react";
import { BrowserSecureClient } from "aegis-fluxion";

export function SecureTimeline() {
  const [status, setStatus] = useState("connecting");

  const client = useMemo(() => {
    return new BrowserSecureClient("wss://api.example.com/socket", {
      autoConnect: false,
      reconnect: true
    });
  }, []);

  useEffect(() => {
    const handleReady = () => setStatus("ready");
    const handleDisconnect = () => setStatus("disconnected");

    client.on("ready", handleReady);
    client.on("disconnect", handleDisconnect);
    client.connect();

    return () => {
      client.off("ready", handleReady);
      client.off("disconnect", handleDisconnect);
      client.disconnect();
    };
  }, [client]);

  return <p>Secure browser socket status: {status}</p>;
}
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

## Chunked streaming quick example

```ts
import { SecureClient, SecureServer } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });
const client = new SecureClient("ws://127.0.0.1:8080");

server.onStream("blob:upload", async (stream, info) => {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const fullBuffer = Buffer.concat(chunks);

  console.log("Received stream", {
    streamId: info.streamId,
    announcedTotalBytes: info.totalBytes,
    receivedBytes: fullBuffer.length
  });
});

client.on("ready", async () => {
  const payload = Buffer.from("large payload");

  const result = await client.emitStream("blob:upload", payload, {
    chunkSizeBytes: 64 * 1024,
    totalBytes: payload.length,
    metadata: { source: "client" }
  });

  console.log(result);
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
- Browser client: [`../browser-client/README.md`](../browser-client/README.md)
- Redis adapter: [`../redis-adapter/README.md`](../redis-adapter/README.md)
- MCP adapter: [`../mcp-adapter/README.md`](../mcp-adapter/README.md)
- Changelog: [`../../CHANGELOG.md`](../../CHANGELOG.md)

---

## License

MIT
