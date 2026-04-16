# @aegis-fluxion/browser-client

Browser-native secure WebSocket client for the `aegis-fluxion` ecosystem.

Version: **0.1.0**

---

## Why this package

`@aegis-fluxion/browser-client` is a lightweight browser SDK that mirrors the
core `SecureClient` messaging model without Node.js built-ins.

It uses only:

- Browser **Web Crypto API** (`crypto.subtle`) for ECDH + AES-256-GCM
- Browser-native **WebSocket** for transport

No `node:crypto`, no `ws`, no Buffer dependency at runtime.

---

## Install

```bash
npm install @aegis-fluxion/browser-client
```

---

## Features

- Ephemeral ECDH handshake (`P-256`) against `SecureServer`
- AES-256-GCM encrypted event envelopes
- Promise/callback ACK flow (`emit(..., { timeoutMs })`)
- Binary payload support (`Uint8Array`, `ArrayBuffer`, `Blob`)
- Encrypted chunked streaming:
  - `emitStream(...)`
  - `onStream(...)`
- Optional reconnect backoff

---

## Basic browser usage

```ts
import { BrowserSecureClient } from "@aegis-fluxion/browser-client";

const client = new BrowserSecureClient("wss://api.example.com/socket", {
  autoConnect: true,
  reconnect: {
    enabled: true,
    initialDelayMs: 250,
    maxDelayMs: 10_000,
    factor: 2,
    jitterRatio: 0.2,
    maxAttempts: null
  }
});

client.on("ready", async () => {
  const ack = await client.emit(
    "notes:create",
    { title: "From browser" },
    { timeoutMs: 1500 }
  );

  console.log("ACK", ack);
});

client.on("notes:created", (payload) => {
  console.log("push event", payload);
});
```

---

## React example

```tsx
import { useEffect, useMemo, useState } from "react";
import { BrowserSecureClient } from "@aegis-fluxion/browser-client";

export function SecureNotesWidget() {
  const [status, setStatus] = useState("connecting");
  const [notes, setNotes] = useState<string[]>([]);

  const client = useMemo(() => {
    return new BrowserSecureClient("wss://api.example.com/socket", {
      autoConnect: false,
      reconnect: true
    });
  }, []);

  useEffect(() => {
    const handleReady = () => setStatus("ready");
    const handleDisconnect = () => setStatus("disconnected");
    const handleNewNote = (payload: unknown) => {
      const data = payload as { title?: string };
      if (typeof data.title === "string") {
        setNotes((prev) => [data.title, ...prev]);
      }
    };

    client.on("ready", handleReady);
    client.on("disconnect", handleDisconnect);
    client.on("notes:created", handleNewNote);

    client.connect();

    return () => {
      client.off("ready", handleReady);
      client.off("disconnect", handleDisconnect);
      client.off("notes:created", handleNewNote);
      client.disconnect();
    };
  }, [client]);

  const createNote = async () => {
    await client.emit("notes:create", { title: "React note" }, { timeoutMs: 1500 });
  };

  return (
    <section>
      <p>Secure socket status: {status}</p>
      <button onClick={createNote}>Create note</button>
      <ul>
        {notes.map((note) => (
          <li key={note}>{note}</li>
        ))}
      </ul>
    </section>
  );
}
```

---

## Chunked stream example

```ts
import { BrowserSecureClient } from "@aegis-fluxion/browser-client";

const client = new BrowserSecureClient("wss://api.example.com/socket");

client.on("ready", async () => {
  const selectedFile = (document.querySelector("#file") as HTMLInputElement)
    .files?.[0];

  if (!selectedFile) {
    return;
  }

  const result = await client.emitStream("files:upload", selectedFile, {
    chunkSizeBytes: 64 * 1024,
    totalBytes: selectedFile.size,
    metadata: { filename: selectedFile.name }
  });

  console.log(result);
});

client.onStream("files:download", async (stream) => {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }

    if (value) {
      chunks.push(value);
    }
  }

  const merged = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
  let offset = 0;

  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  console.log("Downloaded bytes", merged.byteLength);
});
```

---

## API summary

- `new BrowserSecureClient(url, options?)`
- `connect()` / `disconnect(code?, reason?)`
- `isConnected()` / `readyState`
- `on(...)` / `off(...)`
- `emit(event, data, ackOptionsOrCallback?)`
- `emitStream(event, source, options?)`
- `onStream(event, handler)` / `offStream(event, handler)`

---

## Compatibility notes

- Requires a runtime with `WebSocket`, `crypto.subtle`, and `ReadableStream`.
- Designed to connect to `@aegis-fluxion/core` `SecureServer` endpoints.
- This package is transport/client focused; server-side primitives remain in `@aegis-fluxion/core`.

---

## License

MIT
