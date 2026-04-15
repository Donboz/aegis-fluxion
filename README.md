# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.4.0-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is an E2E-encrypted WebSocket toolkit for Node.js/TypeScript.

It provides:

- **Ephemeral ECDH handshake** with **AES-256-GCM** encrypted application frames
- **Secure rooms** for encrypted fanout routing
- **Heartbeat Ping/Pong** for zombie connection cleanup
- **Auto-reconnect with exponential backoff** and fresh tunnel re-handshake
- **RPC-style ACK request/response** over the same encrypted tunnel

---

## Why v0.4.0 matters

`v0.4.0` introduces encrypted **Request-Response (ACK)** messaging.

You can now send events with:

- **Promise-based ACK** (`await` response)
- **Callback-based ACK** (Node-style callback)
- **Timeout protection** (reject/callback error if no response arrives)

All ACK payloads and errors stay inside the E2E encrypted channel.

---

## Installation

```bash
npm install @aegis-fluxion/core ws
```

---

## Quick Example (Encrypted ACK)

### Server

```ts
import { SecureServer } from "@aegis-fluxion/core";

const server = new SecureServer({
  host: "127.0.0.1",
  port: 8080,
  heartbeat: {
    enabled: true,
    intervalMs: 15_000,
    timeoutMs: 15_000
  }
});

server.on("ready", (client) => {
  console.log("secure tunnel ready:", client.id);
});

// RPC handler: return value becomes encrypted ACK response
server.on("user:lookup", async (payload) => {
  const { userId } = payload as { userId: string };

  return {
    userId,
    role: "operator",
    status: "active"
  };
});
```

### Client (Promise ACK)

```ts
import { SecureClient } from "@aegis-fluxion/core";

const client = new SecureClient("ws://127.0.0.1:8080", {
  autoConnect: true,
  reconnect: {
    enabled: true,
    initialDelayMs: 250,
    factor: 2,
    maxDelayMs: 10_000,
    jitterRatio: 0.2,
    maxAttempts: null
  }
});

client.on("ready", async () => {
  const response = await client.emit(
    "user:lookup",
    { userId: "u-42" },
    { timeoutMs: 2000 }
  );

  console.log("ACK response:", response);
});
```

### Client (Callback ACK)

```ts
client.emit(
  "user:lookup",
  { userId: "u-99" },
  { timeoutMs: 2000 },
  (error, response) => {
    if (error) {
      console.error("ACK failed:", error.message);
      return;
    }

    console.log("ACK response:", response);
  }
);
```

---

## Server-to-Client ACK

Use `emitTo` with Promise or callback:

```ts
server.on("ready", async (client) => {
  const response = await server.emitTo(
    client.id,
    "agent:health",
    { verbose: true },
    { timeoutMs: 1500 }
  );

  console.log("client ACK:", response);
});
```

On the client side:

```ts
client.on("agent:health", () => {
  return { ok: true, uptimeSec: process.uptime() };
});
```

---

## Resilience & Security

- **Heartbeat** removes dead sockets and clears encryption material in memory
- **Reconnect** retries transport with configurable exponential backoff
- **Fresh handshake** runs after reconnect for new key derivation
- **Tamper resistance**: AES-GCM auth failures are dropped
- **Timeout safety**: pending ACK requests fail fast instead of hanging forever

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

## Package Docs

Detailed API documentation and advanced usage examples are available in:

- `packages/core/README.md`

---

## Publish (Monorepo)

```bash
npm whoami
npm run release:core
```

---

## License

MIT
