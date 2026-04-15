# aegis-fluxion

Main end-user package for the `aegis-fluxion` secure messaging toolkit.

This package re-exports the full public API from `@aegis-fluxion/core` (including
`SecureServer`, `SecureClient`, `SecureServerClient`, and related types).

---

## Installation

```bash
npm install aegis-fluxion ws
```

---

## Quick Start

```ts
import { SecureServer, SecureClient } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });

server.on("profile:get", ({ id }) => {
  return { id, role: "operator" };
});

const client = new SecureClient("ws://127.0.0.1:8080");

client.on("ready", async () => {
  const profile = await client.emit(
    "profile:get",
    { id: "u-42" },
    { timeoutMs: 1500 }
  );

  console.log(profile);
});
```

Callback-style ACK usage:

```ts
client.emit(
  "profile:get",
  { id: "u-7" },
  { timeoutMs: 1500 },
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

## Capabilities

- ECDH key exchange + AES-256-GCM encrypted transport
- Secure room fanout routing
- Heartbeat-based stale socket cleanup
- Auto-reconnect with exponential backoff
- Encrypted ACK request/response with timeout control

---

## Related Docs

- Core technical docs: [`../core/README.md`](../core/README.md)
- Repository changelog: [`../../CHANGELOG.md`](../../CHANGELOG.md)

---

## License

MIT
