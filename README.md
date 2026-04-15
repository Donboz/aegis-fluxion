# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.4.0-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is an end-to-end encrypted WebSocket toolkit for Node.js and TypeScript.

This repository is a monorepo containing:

| Package | Purpose |
| --- | --- |
| `aegis-fluxion` | Main end-user umbrella package (recommended) |
| `@aegis-fluxion/core` | Low-level core primitives |

---

## Key Capabilities

- Ephemeral ECDH handshake (`prime256v1`) for per-session key exchange
- AES-256-GCM encrypted message envelopes
- Secure room routing (`join`, `leave`, `to(room).emit`)
- Heartbeat Ping/Pong zombie cleanup
- Auto-reconnect with exponential backoff and fresh re-handshake
- Encrypted RPC-style ACK request/response with timeout protection

---

## Install

### Recommended (umbrella package)

```bash
npm install aegis-fluxion ws
```

### Low-level core only

```bash
npm install @aegis-fluxion/core ws
```

---

## Quick Start (ACK over encrypted tunnel)

```ts
import { SecureServer, SecureClient } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.on("user:lookup", ({ userId }) => {
  return { userId, role: "operator", status: "active" };
});

const client = new SecureClient("ws://127.0.0.1:8080");

client.on("ready", async () => {
  const response = await client.emit(
    "user:lookup",
    { userId: "u-42" },
    { timeoutMs: 2000 }
  );

  console.log(response);
});
```

Callback-style ACK is also supported:

```ts
client.emit(
  "user:lookup",
  { userId: "u-99" },
  { timeoutMs: 2000 },
  (error, response) => {
    if (error) {
      console.error(error.message);
      return;
    }

    console.log(response);
  }
);
```

---

## Security & Reliability Notes

- ACK request/response payloads are encrypted like all other application events.
- Internal transport events are reserved and protected from manual emission.
- Tampered AES-GCM frames are dropped.
- Pending ACK requests are cleaned on timeout/disconnect.

---

## Changelog

See [`CHANGELOG.md`](./CHANGELOG.md) for release history from `0.1.0` to `0.4.0`.

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

## Publish

From repository root:

```bash
npm run publish:core
npm run publish:umbrella
```

---

## License

MIT
