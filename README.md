# aegis-fluxion

![Version](https://img.shields.io/badge/version-0.5.0-2563eb)
![Node](https://img.shields.io/badge/node-%3E%3D18.18.0-16a34a)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178c6)
![Crypto](https://img.shields.io/badge/Crypto-ECDH%20%2B%20AES--256--GCM-0f172a)

`aegis-fluxion` is an end-to-end encrypted WebSocket toolkit for Node.js and TypeScript.

It provides a secure event channel with ephemeral ECDH key exchange, AES-256-GCM encryption,
encrypted ACK request/response, and **native binary payload support** for `Buffer`, `Uint8Array`,
and `Blob`.

---

## Packages

| Package | Purpose |
| --- | --- |
| `aegis-fluxion` | Main end-user package (recommended) |
| `@aegis-fluxion/core` | Low-level primitives and transport internals |

---

## What's New in 0.5.0

- Binary data support over encrypted channels (`Buffer`, `Uint8Array`, `Blob`)
- Type-preserving binary roundtrip in both direct events and ACK flows
- Nested payload support (JSON + binary in the same message)

---

## Install

```bash
npm install aegis-fluxion ws
```

---

## Quick Start (Encrypted Binary + ACK)

```ts
import { SecureServer, SecureClient } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.on("binary:inspect", async (payload) => {
  const { file, bytes, blob } = payload as {
    file: Buffer;
    bytes: Uint8Array;
    blob: Blob;
  };

  return {
    fileSize: file.byteLength,
    bytesSize: bytes.byteLength,
    blobSize: blob.size,
    blobType: blob.type
  };
});

const client = new SecureClient("ws://127.0.0.1:8080");

client.on("ready", async () => {
  const result = await client.emit(
    "binary:inspect",
    {
      file: Buffer.from("hello-binary"),
      bytes: Uint8Array.from([10, 20, 30, 40]),
      blob: new Blob([Buffer.from("blob-bytes")], {
        type: "application/octet-stream"
      })
    },
    { timeoutMs: 2000 }
  );

  console.log(result);
});
```

---

## Binary Payload Behavior

- `Buffer` arrives as `Buffer`
- `Uint8Array` arrives as `Uint8Array`
- `Blob` arrives as `Blob` (falls back to `Buffer` if `Blob` is unavailable in runtime)
- Binary values can be nested inside regular JSON objects/arrays

---

## Security Model

- Ephemeral ECDH (`prime256v1`) derives per-session secrets
- AES-256-GCM encrypts all application payloads (JSON and binary)
- GCM authentication tag enforces tamper detection and integrity
- Internal transport events are reserved and blocked from manual emit

---

## Reliability Features

- Heartbeat Ping/Pong stale-connection cleanup
- Client auto-reconnect with exponential backoff and jitter
- Fresh re-handshake and key derivation after reconnect
- Promise and callback ACK APIs with per-request timeouts

---

## Changelog

See [`CHANGELOG.md`](./CHANGELOG.md) for complete release history.

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

## License

MIT
