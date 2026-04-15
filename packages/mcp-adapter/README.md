# @aegis-fluxion/mcp-adapter

Encrypted MCP transport adapter for the `aegis-fluxion` ecosystem.

This package provides `SecureMCPTransport`, a JSON-RPC 2.0 transport that carries MCP-compatible
messages over `@aegis-fluxion/core` encrypted WebSocket tunnels (`SecureClient`/`SecureServer`).

Version: **0.7.0**

---

## Why this package

- Replace stdio/SSE transport with encrypted WebSocket tunnels
- Reuse existing ECDH + AES-256-GCM channel security
- Bind one server-side transport to one authenticated socket (`clientId`)
- Keep MCP message format strict with normalization and guards

---

## Install

```bash
npm install @aegis-fluxion/mcp-adapter @aegis-fluxion/core ws
```

---

## Core API

### `SecureMCPTransport`

```ts
new SecureMCPTransport({
  mode: "client",
  client: secureClient,
  channel?: "mcp:jsonrpc",
  connectTimeoutMs?: 10000
});

new SecureMCPTransport({
  mode: "server",
  server: secureServer,
  clientId: "socket-id",
  channel?: "mcp:jsonrpc",
  closeCode?: 1000,
  closeReason?: "Secure MCP transport closed."
});
```

Lifecycle and messaging methods:

- `start(): Promise<void>`
- `send(message: SecureMCPMessage): Promise<void>`
- `close(): Promise<void>`
- `onmessage?: (message) => void | Promise<void>`
- `onerror?: (error) => void | Promise<void>`
- `onclose?: () => void | Promise<void>`

---

## End-to-end example (client + server transport)

```ts
import { SecureClient, SecureServer } from "@aegis-fluxion/core";
import { SecureMCPTransport, type SecureMCPMessage } from "@aegis-fluxion/mcp-adapter";

const secureServer = new SecureServer({ host: "127.0.0.1", port: 9093 });

secureServer.use(async (context, next) => {
  if (context.phase === "connection") {
    const authHeader = context.request.headers.authorization;
    const token = Array.isArray(authHeader) ? authHeader[0] : authHeader;

    if (token !== "Bearer mcp-secure-token") {
      throw new Error("Unauthorized MCP client");
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
    // Bridge into your MCP server runtime here.
    console.log("Incoming MCP message on server", message);
  };

  await serverTransport.start();
});

const secureClient = new SecureClient("ws://127.0.0.1:9093", {
  wsOptions: {
    headers: {
      authorization: "Bearer mcp-secure-token"
    }
  }
});

const clientTransport = new SecureMCPTransport({
  mode: "client",
  client: secureClient
});

clientTransport.onmessage = async (message: SecureMCPMessage) => {
  console.log("Incoming MCP message on client", message);
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

## Message helpers

The package exports guards and normalization helpers to harden integration points:

- `normalizeSecureMCPMessage(candidate)`
- `isSecureMCPRequest(message)`
- `isSecureMCPNotification(message)`
- `isSecureMCPResponse(message)`

---

## Security notes

- MCP message payloads are transported through the same encrypted channel as application events.
- Handshake and key lifecycle are managed by `@aegis-fluxion/core`.
- Server transport mode routes messages to a specific socket by `clientId`, reducing accidental
  cross-session fanout.

---

## License

MIT
