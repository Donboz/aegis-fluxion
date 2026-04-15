import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import WebSocket from "ws";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SecureClient, SecureServer } from "../src/index";

const TEST_TIMEOUT_MS = 6000;

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeoutHandle = setTimeout(() => {
      reject(new Error(`Timeout while waiting for ${label}.`));
    }, timeoutMs);

    promise
      .then((value) => {
        clearTimeout(timeoutHandle);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timeoutHandle);
        reject(error);
      });
  });
}

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();

    server.on("error", (error) => {
      reject(error);
    });

    server.listen(0, "127.0.0.1", () => {
      const address = server.address();

      if (!address || typeof address === "string") {
        server.close(() => {
          reject(new Error("Failed to resolve a free TCP port."));
        });
        return;
      }

      const selectedPort = address.port;
      server.close((closeError) => {
        if (closeError) {
          reject(closeError);
          return;
        }

        resolve(selectedPort);
      });
    });
  });
}

function createTamperedPacket(): Buffer {
  const packetVersion = Buffer.from([1]);
  const iv = randomBytes(12);
  const authTag = randomBytes(16);
  const forgedCiphertext = randomBytes(32);

  return Buffer.concat([packetVersion, iv, authTag, forgedCiphertext]);
}

describe("SecureServer and SecureClient encryption flow", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("establishes encrypted communication and delivers application payloads", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);

    try {
      const serverReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          server.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "server ready event"
      );

      const clientReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          client.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client ready event"
      );

      const serverReceivedPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          server.on("ping", (data, serverClient) => {
            resolve(data);
            server.emitTo(serverClient.id, "pong", { message: "pong" });
          });
        }),
        TEST_TIMEOUT_MS,
        "server encrypted message"
      );

      const clientReceivedPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          client.on("pong", (data) => {
            resolve(data);
          });
        }),
        TEST_TIMEOUT_MS,
        "client encrypted response"
      );

      await withTimeout(
        new Promise<void>((resolve) => {
          client.on("connect", () => {
            const emitted = client.emit("ping", { message: "ping" });
            expect(emitted).toBe(true);
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client connect event"
      );

      await Promise.all([serverReadyPromise, clientReadyPromise]);

      const [serverPayload, clientPayload] = await Promise.all([
        serverReceivedPromise,
        clientReceivedPromise
      ]);

      expect(serverPayload).toEqual({ message: "ping" });
      expect(clientPayload).toEqual({ message: "pong" });
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("drops tampered encrypted payloads without crashing the transport", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);

    try {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {
        return undefined;
      });

      let didReceiveUnexpectedPayload = false;

      server.on("tampered-event", () => {
        didReceiveUnexpectedPayload = true;
      });

      server.on("healthcheck", (data, serverClient) => {
        server.emitTo(serverClient.id, "healthcheck-ack", {
          ok: true,
          request: data
        });
      });

      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready event"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready event"
        )
      ]);

      const unsafeClientSocket = (
        client as unknown as { socket: WebSocket | null }
      ).socket;

      if (!unsafeClientSocket || unsafeClientSocket.readyState !== WebSocket.OPEN) {
        throw new Error("Unsafe socket accessor was unavailable for tampering simulation.");
      }

      unsafeClientSocket.send(createTamperedPacket());
      await wait(80);

      expect(didReceiveUnexpectedPayload).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith("Tampered data detected and dropped");
      expect(client.isConnected()).toBe(true);

      const ackPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          client.on("healthcheck-ack", (data) => {
            resolve(data);
          });
        }),
        TEST_TIMEOUT_MS,
        "post-tamper ack"
      );

      expect(client.emit("healthcheck", { step: "after-tamper" })).toBe(true);

      const ackPayload = await ackPromise;

      expect(ackPayload).toEqual({
        ok: true,
        request: { step: "after-tamper" }
      });
      expect(client.isConnected()).toBe(true);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });
});
