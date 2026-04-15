# aegis-fluxion

Main end-user package for the `aegis-fluxion` secure messaging toolkit.

This package re-exports the full public API from `@aegis-fluxion/core`, including
`SecureServer`, `SecureClient`, and all related types.

Version: **0.5.0**

---

## Installation

```bash
npm install aegis-fluxion ws
```

---

## Why `aegis-fluxion`

- ECDH + AES-256-GCM encrypted transport
- Encrypted ACK request/response with timeout control
- Room-based secure fanout
- Heartbeat cleanup + reconnect resilience
- **Binary support out of the box** (`Buffer`, `Uint8Array`, `Blob`)

---

## Quick Start (Binary Upload Metadata)

```ts
import { SecureClient, SecureServer } from "aegis-fluxion";

const server = new SecureServer({ host: "127.0.0.1", port: 8080 });
const client = new SecureClient("ws://127.0.0.1:8080");

server.on("file:upload", async (payload) => {
  const { name, chunk, previewBlob } = payload as {
    name: string;
    chunk: Uint8Array;
    previewBlob: Blob;
  };

  return {
    name,
    chunkBytes: chunk.byteLength,
    previewBytes: previewBlob.size
  };
});

client.on("ready", async () => {
  const response = await client.emit(
    "file:upload",
    {
      name: "avatar.png",
      chunk: Uint8Array.from([137, 80, 78, 71]),
      previewBlob: new Blob([Buffer.from("tiny-preview")], {
        type: "image/png"
      })
    },
    { timeoutMs: 2000 }
  );

  console.log(response);
});
```

---

## Callback-style ACK Example

```ts
client.emit(
  "file:upload",
  {
    name: "report.bin",
    chunk: Buffer.from("01020304", "hex"),
    previewBlob: new Blob([Buffer.from("ok")], {
      type: "application/octet-stream"
    })
  },
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

## Binary Payload Notes

- Binary integrity is protected by AES-GCM authentication tags.
- Payload type is preserved across encrypted transport.
- Mixed payloads (JSON + binary) are supported.

---

## Related Docs

- Core package docs: [`../core/README.md`](../core/README.md)
- Repository changelog: [`../../CHANGELOG.md`](../../CHANGELOG.md)

---

## License

MIT
