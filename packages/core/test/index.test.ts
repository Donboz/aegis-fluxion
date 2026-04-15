import { createECDH, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import WebSocket from "ws";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  SecureClient,
  SecureServer,
  type SecureServerAdapter,
  type SecureServerAdapterMessage
} from "../src/index";

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

class InMemorySecureServerAdapter implements SecureServerAdapter {
  private static readonly adapters = new Set<InMemorySecureServerAdapter>();

  private server: SecureServer | null = null;

  public async attach(server: SecureServer): Promise<void> {
    this.server = server;
    InMemorySecureServerAdapter.adapters.add(this);
  }

  public async publish(message: SecureServerAdapterMessage): Promise<void> {
    const peerAdapters = [...InMemorySecureServerAdapter.adapters].filter(
      (adapter) => adapter !== this && adapter.server !== null
    );

    for (const adapter of peerAdapters) {
      await adapter.server?.handleAdapterMessage(message);
    }
  }

  public async detach(server: SecureServer): Promise<void> {
    if (this.server !== server) {
      return;
    }

    this.server = null;
    InMemorySecureServerAdapter.adapters.delete(this);
  }
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

  it("supports secure room join/leave and room-scoped encrypted emits", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const clientA = new SecureClient(`ws://127.0.0.1:${port}`);
    const clientB = new SecureClient(`ws://127.0.0.1:${port}`);

    try {
      const readySockets: Array<{
        id: string;
        join: (room: string) => boolean;
        leave: (room: string) => boolean;
      }> = [];

      const serverReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          server.on("ready", (socket) => {
            readySockets.push(socket);

            if (readySockets.length === 2) {
              resolve();
            }
          });
        }),
        TEST_TIMEOUT_MS,
        "both server sockets ready"
      );

      const clientReadyPromiseA = withTimeout(
        new Promise<void>((resolve) => {
          clientA.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client A ready event"
      );

      const clientReadyPromiseB = withTimeout(
        new Promise<void>((resolve) => {
          clientB.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client B ready event"
      );

      await Promise.all([
        serverReadyPromise,
        clientReadyPromiseA,
        clientReadyPromiseB
      ]);

      const [socketA, socketB] = readySockets;

      expect(socketA.join("agents:secure")).toBe(true);
      expect(socketA.join("agents:secure")).toBe(false);
      expect(socketB.join("agents:secure")).toBe(true);
      expect(socketB.leave("agents:secure")).toBe(true);
      expect(socketB.leave("agents:secure")).toBe(false);

      let didClientBReceiveRoomMessage = false;
      clientB.on("room:message", () => {
        didClientBReceiveRoomMessage = true;
      });

      const roomMessagePromiseA = withTimeout(
        new Promise<unknown>((resolve) => {
          clientA.on("room:message", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "room message for client A"
      );

      server.to("agents:secure").emit("room:message", {
        source: "server",
        secure: true
      });

      const roomPayloadA = await roomMessagePromiseA;

      expect(roomPayloadA).toEqual({
        source: "server",
        secure: true
      });

      await wait(120);
      expect(didClientBReceiveRoomMessage).toBe(false);

      const directMessagePromiseB = withTimeout(
        new Promise<unknown>((resolve) => {
          clientB.on("direct:message", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "direct message for client B"
      );

      expect(
        server.emitTo(socketB.id, "direct:message", {
          source: "server",
          secure: true
        })
      ).toBe(true);

      const directPayloadB = await directMessagePromiseB;

      expect(directPayloadB).toEqual({
        source: "server",
        secure: true
      });
      expect(clientA.isConnected()).toBe(true);
      expect(clientB.isConnected()).toBe(true);
    } finally {
      clientA.disconnect();
      clientB.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("replicates broadcast and room events across server instances via adapter hooks", async () => {
    const portA = await getFreePort();
    const portB = await getFreePort();

    const adapterA = new InMemorySecureServerAdapter();
    const adapterB = new InMemorySecureServerAdapter();

    const serverA = new SecureServer({
      port: portA,
      host: "127.0.0.1",
      adapter: adapterA
    });

    const serverB = new SecureServer({
      port: portB,
      host: "127.0.0.1",
      adapter: adapterB
    });

    const clientA = new SecureClient(`ws://127.0.0.1:${portA}`, {
      reconnect: false
    });

    const clientB = new SecureClient(`ws://127.0.0.1:${portB}`, {
      reconnect: false
    });

    try {
      const serverReadyA = withTimeout(
        new Promise<string>((resolve) => {
          serverA.on("ready", (client) => {
            resolve(client.id);
          });
        }),
        TEST_TIMEOUT_MS,
        "server A ready for adapter replication"
      );

      const serverReadyB = withTimeout(
        new Promise<string>((resolve) => {
          serverB.on("ready", (client) => {
            resolve(client.id);
          });
        }),
        TEST_TIMEOUT_MS,
        "server B ready for adapter replication"
      );

      const clientReadyA = withTimeout(
        new Promise<void>((resolve) => {
          clientA.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client A ready for adapter replication"
      );

      const clientReadyB = withTimeout(
        new Promise<void>((resolve) => {
          clientB.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client B ready for adapter replication"
      );

      const [, serverBClientId] = await Promise.all([
        serverReadyA,
        serverReadyB,
        clientReadyA,
        clientReadyB
      ]);

      const serverBClient = serverB.clients.get(serverBClientId);

      if (!serverBClient) {
        throw new Error("Failed to resolve server B client for adapter room join.");
      }

      expect(serverBClient.join("cluster:ops")).toBe(true);

      const replicatedBroadcastPayload = withTimeout(
        new Promise<unknown>((resolve) => {
          clientB.on("cluster:broadcast", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "replicated broadcast payload"
      );

      expect(
        serverA.emit("cluster:broadcast", {
          source: "server-a",
          kind: "broadcast"
        })
      ).toBe(serverA);

      expect(await replicatedBroadcastPayload).toEqual({
        source: "server-a",
        kind: "broadcast"
      });

      let didClientAReceiveRoomEvent = false;

      clientA.on("cluster:room", () => {
        didClientAReceiveRoomEvent = true;
      });

      const replicatedRoomPayload = withTimeout(
        new Promise<unknown>((resolve) => {
          clientB.on("cluster:room", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "replicated room payload"
      );

      serverA.to("cluster:ops").emit("cluster:room", {
        source: "server-a",
        kind: "room"
      });

      expect(await replicatedRoomPayload).toEqual({
        source: "server-a",
        kind: "room"
      });

      await wait(80);
      expect(didClientAReceiveRoomEvent).toBe(false);
    } finally {
      await adapterA.detach(serverA);
      await adapterB.detach(serverB);
      clientA.disconnect();
      clientB.disconnect();
      serverA.close();
      serverB.close();
      await wait(30);
    }
  });

  it("supports encrypted ACK request-response from client using Promise and callback", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);

    try {
      server.on("math:add", (payload) => {
        const parsedPayload = payload as { a: number; b: number };

        return {
          total: parsedPayload.a + parsedPayload.b
        };
      });

      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready for client ACK test"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for client ACK test"
        )
      ]);

      const promiseAckResponse = await withTimeout(
        client.emit(
          "math:add",
          { a: 7, b: 5 },
          { timeoutMs: 750 }
        ) as Promise<unknown>,
        TEST_TIMEOUT_MS,
        "client ACK promise response"
      );

      expect(promiseAckResponse).toEqual({ total: 12 });

      const callbackAckResponse = await withTimeout(
        new Promise<unknown>((resolve, reject) => {
          const emitted = client.emit(
            "math:add",
            { a: 10, b: 15 },
            { timeoutMs: 750 },
            (error, response) => {
              if (error) {
                reject(error);
                return;
              }

              resolve(response);
            }
          );

          expect(emitted).toBe(true);
        }),
        TEST_TIMEOUT_MS,
        "client ACK callback response"
      );

      expect(callbackAckResponse).toEqual({ total: 25 });
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("supports encrypted ACK request-response from server emitTo and applies timeout", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);

    try {
      client.on("profile:fetch", (payload) => {
        const parsedPayload = payload as { include: string[] };

        return {
          id: "agent-7",
          include: parsedPayload.include
        };
      });

      client.on("never:respond", () => {
        return new Promise(() => {
          return undefined;
        });
      });

      const serverReadyClientPromise = withTimeout(
        new Promise<string>((resolve) => {
          server.on("ready", (socket) => {
            resolve(socket.id);
          });
        }),
        TEST_TIMEOUT_MS,
        "server ready with client id for emitTo ACK test"
      );

      const clientReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          client.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client ready for emitTo ACK test"
      );

      const [clientId] = await Promise.all([serverReadyClientPromise, clientReadyPromise]);

      const promiseAckResponse = await withTimeout(
        server.emitTo(
          clientId,
          "profile:fetch",
          { include: ["id", "roles"] },
          { timeoutMs: 750 }
        ) as Promise<unknown>,
        TEST_TIMEOUT_MS,
        "server emitTo ACK promise response"
      );

      expect(promiseAckResponse).toEqual({
        id: "agent-7",
        include: ["id", "roles"]
      });

      const callbackAckResponse = await withTimeout(
        new Promise<unknown>((resolve, reject) => {
          const emitted = server.emitTo(
            clientId,
            "profile:fetch",
            { include: ["permissions"] },
            { timeoutMs: 750 },
            (error, response) => {
              if (error) {
                reject(error);
                return;
              }

              resolve(response);
            }
          );

          expect(emitted).toBe(true);
        }),
        TEST_TIMEOUT_MS,
        "server emitTo ACK callback response"
      );

      expect(callbackAckResponse).toEqual({
        id: "agent-7",
        include: ["permissions"]
      });

      await expect(
        server.emitTo(clientId, "never:respond", { probe: true }, { timeoutMs: 110 })
      ).rejects.toThrow(/timed out/i);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("transfers Buffer payloads over encrypted channel without mutation", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);
    const sourcePayload = randomBytes(128);

    try {
      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready for binary buffer test"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for binary buffer test"
        )
      ]);

      const serverReceivedPromise = withTimeout(
        new Promise<void>((resolve, reject) => {
          server.on("binary:ingest", (payload, serverClient) => {
            try {
              expect(Buffer.isBuffer(payload)).toBe(true);
              expect((payload as Buffer).equals(sourcePayload)).toBe(true);
              server.emitTo(serverClient.id, "binary:echo", payload);
              resolve();
            } catch (error) {
              reject(error);
            }
          });
        }),
        TEST_TIMEOUT_MS,
        "server receive binary buffer"
      );

      const clientEchoPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          client.on("binary:echo", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "client binary echo"
      );

      expect(client.emit("binary:ingest", sourcePayload)).toBe(true);

      await serverReceivedPromise;

      const echoedPayload = await clientEchoPromise;

      expect(Buffer.isBuffer(echoedPayload)).toBe(true);
      expect((echoedPayload as Buffer).equals(sourcePayload)).toBe(true);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("supports Buffer, Uint8Array and Blob in encrypted ACK roundtrip", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);

    const sourceBuffer = Buffer.from("binary-buffer-payload", "utf8");
    const sourceUint8Array = Uint8Array.from([1, 3, 5, 7, 9, 11, 13]);
    const sourceBlob = new Blob([Buffer.from("binary-blob-payload", "utf8")], {
      type: "application/octet-stream"
    });

    try {
      const sourceBlobBuffer = Buffer.from(await sourceBlob.arrayBuffer());

      server.on("binary:mixed", async (payload) => {
        const parsedPayload = payload as {
          buffer: Buffer;
          bytes: Uint8Array;
          blob: Blob;
        };

        expect(Buffer.isBuffer(parsedPayload.buffer)).toBe(true);
        expect(parsedPayload.buffer.equals(sourceBuffer)).toBe(true);
        expect(parsedPayload.bytes).toBeInstanceOf(Uint8Array);
        expect(Buffer.from(parsedPayload.bytes).equals(Buffer.from(sourceUint8Array))).toBe(true);
        expect(parsedPayload.blob).toBeInstanceOf(Blob);

        const receivedBlobBuffer = Buffer.from(await parsedPayload.blob.arrayBuffer());
        expect(receivedBlobBuffer.equals(sourceBlobBuffer)).toBe(true);

        return {
          buffer: parsedPayload.buffer,
          bytes: parsedPayload.bytes,
          blob: parsedPayload.blob
        };
      });

      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready for mixed binary ACK"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for mixed binary ACK"
        )
      ]);

      const ackResponse = await withTimeout(
        client.emit(
          "binary:mixed",
          {
            buffer: sourceBuffer,
            bytes: sourceUint8Array,
            blob: sourceBlob
          },
          { timeoutMs: 1200 }
        ) as Promise<unknown>,
        TEST_TIMEOUT_MS,
        "mixed binary ACK response"
      );

      const parsedAckResponse = ackResponse as {
        buffer: Buffer;
        bytes: Uint8Array;
        blob: Blob;
      };

      expect(Buffer.isBuffer(parsedAckResponse.buffer)).toBe(true);
      expect(parsedAckResponse.buffer.equals(sourceBuffer)).toBe(true);
      expect(parsedAckResponse.bytes).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(parsedAckResponse.bytes).equals(Buffer.from(sourceUint8Array))).toBe(true);
      expect(parsedAckResponse.blob).toBeInstanceOf(Blob);

      const ackBlobBuffer = Buffer.from(await parsedAckResponse.blob.arrayBuffer());
      expect(ackBlobBuffer.equals(sourceBlobBuffer)).toBe(true);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("times out client ACK requests when server handler never resolves", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`);

    try {
      server.on("never:respond:server", () => {
        return new Promise(() => {
          return undefined;
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
          "server ready for client ACK timeout"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for client ACK timeout"
        )
      ]);

      await expect(
        client.emit("never:respond:server", { probe: true }, { timeoutMs: 110 })
      ).rejects.toThrow(/timed out/i);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("cleans zombie sockets and in-memory keys when heartbeat pings are not acknowledged", async () => {
    const port = await getFreePort();
    const server = new SecureServer({
      port,
      host: "127.0.0.1",
      heartbeat: {
        intervalMs: 40,
        timeoutMs: 80
      }
    });
    const client = new SecureClient(`ws://127.0.0.1:${port}`, {
      reconnect: false
    });

    try {
      const serverReadyPromise = withTimeout(
        new Promise<string>((resolve) => {
          server.on("ready", (socket) => {
            resolve(socket.id);
          });
        }),
        TEST_TIMEOUT_MS,
        "server ready event for heartbeat test"
      );

      const clientReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          client.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "client ready event for heartbeat test"
      );

      const [readyClientId] = await Promise.all([serverReadyPromise, clientReadyPromise]);

      const unsafeClientSocket = (
        client as unknown as { socket: WebSocket | null }
      ).socket;

      if (!unsafeClientSocket || unsafeClientSocket.readyState !== WebSocket.OPEN) {
        throw new Error("Unsafe socket accessor was unavailable for heartbeat test.");
      }

      const blockPongSpy = vi
        .spyOn(unsafeClientSocket, "pong")
        .mockImplementation(() => {
          return undefined;
        });

      const disconnectPromise = withTimeout(
        new Promise<{ code: number; reason: string }>((resolve) => {
          server.on("disconnect", (socket, code, reason) => {
            if (socket.id === readyClientId) {
              resolve({ code, reason });
            }
          });
        }),
        TEST_TIMEOUT_MS,
        "heartbeat disconnect event"
      );

      const disconnectPayload = await disconnectPromise;

      const internalServerState = server as unknown as {
        encryptionKeyBySocket: WeakMap<WebSocket, Buffer>;
        sharedSecretBySocket: WeakMap<WebSocket, Buffer>;
      };

      expect(blockPongSpy).toHaveBeenCalled();
      expect(disconnectPayload.code).toBe(1006);
      expect(server.clientCount).toBe(0);
      expect(internalServerState.encryptionKeyBySocket.get(unsafeClientSocket)).toBeUndefined();
      expect(internalServerState.sharedSecretBySocket.get(unsafeClientSocket)).toBeUndefined();
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("automatically reconnects with backoff and re-establishes a fresh encrypted tunnel", async () => {
    const port = await getFreePort();
    let server = new SecureServer({ port, host: "127.0.0.1" });

    const attachProbeHandlers = (target: SecureServer): void => {
      target.on("resilience:probe", (payload, socket) => {
        target.emitTo(socket.id, "resilience:ack", {
          ok: true,
          probe: payload
        });
      });
    };

    attachProbeHandlers(server);

    const client = new SecureClient(`ws://127.0.0.1:${port}`, {
      reconnect: {
        enabled: true,
        initialDelayMs: 30,
        maxDelayMs: 120,
        factor: 2,
        jitterRatio: 0,
        maxAttempts: 20
      }
    });

    try {
      let firstHandshakePublicKey: string | null = null;

      const secondReadyPromise = withTimeout(
        new Promise<string>((resolve, reject) => {
          client.on("ready", () => {
            const handshakeState = (
              client as unknown as { handshakeState?: { localPublicKey?: unknown } }
            ).handshakeState;

            if (!handshakeState || typeof handshakeState.localPublicKey !== "string") {
              reject(new Error("Handshake state was unavailable on ready event."));
              return;
            }

            if (firstHandshakePublicKey === null) {
              firstHandshakePublicKey = handshakeState.localPublicKey;
              return;
            }

            resolve(handshakeState.localPublicKey);
          });
        }),
        TEST_TIMEOUT_MS,
        "second ready event after reconnect"
      );

      await withTimeout(
        new Promise<void>((resolve) => {
          const checkFirstReady = (): void => {
            if (firstHandshakePublicKey !== null) {
              resolve();
              return;
            }

            setTimeout(checkFirstReady, 10);
          };

          checkFirstReady();
        }),
        TEST_TIMEOUT_MS,
        "first ready event"
      );

      server.close();
      await wait(120);

      server = new SecureServer({ port, host: "127.0.0.1" });
      attachProbeHandlers(server);

      const secondHandshakePublicKey = await secondReadyPromise;

      expect(firstHandshakePublicKey).not.toBeNull();
      expect(secondHandshakePublicKey).not.toBe(firstHandshakePublicKey);

      const ackPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          client.on("resilience:ack", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "reconnected encrypted ack"
      );

      expect(
        client.emit("resilience:probe", {
          attempt: "after-reconnect"
        })
      ).toBe(true);

      const ackPayload = await ackPromise;

      expect(ackPayload).toEqual({
        ok: true,
        probe: {
          attempt: "after-reconnect"
        }
      });
      expect(client.isConnected()).toBe(true);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("resumes secure session with cached ticket and skips extra ECDH computeSecret", async () => {
    const port = await getFreePort();
    const server = new SecureServer({
      port,
      host: "127.0.0.1",
      sessionResumption: {
        enabled: true,
        ticketTtlMs: 60_000,
        maxCachedTickets: 256
      }
    });

    const client = new SecureClient(`ws://127.0.0.1:${port}`, {
      reconnect: false,
      sessionResumption: {
        enabled: true,
        maxAcceptedTicketTtlMs: 60_000
      }
    });

    const ecdhPrototype = Object.getPrototypeOf(createECDH("prime256v1")) as {
      computeSecret: (...args: unknown[]) => Buffer;
    };

    const computeSecretSpy = vi.spyOn(ecdhPrototype, "computeSecret");

    try {
      const firstServerReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          server.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "first server ready for resume test"
      );

      const firstClientReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          client.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "first client ready for resume test"
      );

      await Promise.all([firstServerReadyPromise, firstClientReadyPromise]);

      const computeSecretCallsAfterInitialHandshake = computeSecretSpy.mock.calls.length;

      expect(computeSecretCallsAfterInitialHandshake).toBeGreaterThanOrEqual(2);

      await withTimeout(
        new Promise<void>((resolve) => {
          const ensureTicketCached = (): void => {
            if ((client as unknown as { sessionTicket?: unknown }).sessionTicket) {
              resolve();
              return;
            }

            setTimeout(ensureTicketCached, 10);
          };

          ensureTicketCached();
        }),
        TEST_TIMEOUT_MS,
        "session ticket cache population"
      );

      const disconnectPromise = withTimeout(
        new Promise<void>((resolve) => {
          client.on("disconnect", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "manual disconnect before resume"
      );

      client.disconnect();
      await disconnectPromise;
      await wait(40);

      const secondServerReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          server.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "second server ready for resume test"
      );

      const secondClientReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          client.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "second client ready for resume test"
      );

      client.connect();

      await Promise.all([secondServerReadyPromise, secondClientReadyPromise]);

      const computeSecretCallsAfterResume = computeSecretSpy.mock.calls.length;
      expect(computeSecretCallsAfterResume).toBe(
        computeSecretCallsAfterInitialHandshake
      );

      const internalHandshakeState = (
        client as unknown as {
          handshakeState?: {
            resumeAttempt?: {
              status?: string;
            } | null;
          };
        }
      ).handshakeState;

      expect(internalHandshakeState?.resumeAttempt?.status).toBe("accepted");

      server.on("resume:probe", (payload, serverClient) => {
        serverClient.emit("resume:ack", payload);
      });

      const ackPayloadPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          client.on("resume:ack", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "resume transport ack"
      );

      expect(client.emit("resume:probe", { probe: "resumed" })).toBe(true);
      expect(await ackPayloadPromise).toEqual({ probe: "resumed" });
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("runs connection middleware before handshake and rejects unauthorized clients", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });

    let unauthorizedErrorObserved = false;

    server.on("error", (error) => {
      if (/unauthorized api key/i.test(error.message)) {
        unauthorizedErrorObserved = true;
      }
    });

    server.use(async (context, next) => {
      if (context.phase !== "connection") {
        await next();
        return;
      }

      const headerValue = context.request.headers["x-api-key"];
      const apiKey = Array.isArray(headerValue) ? headerValue[0] : headerValue;

      if (apiKey !== "aegis-secret-key") {
        throw new Error("Unauthorized API key");
      }

      context.metadata.set("auth.subject", "integration-user");
      await next();
    });

    const unauthorizedSocket = new WebSocket(`ws://127.0.0.1:${port}`);
    const authorizedClient = new SecureClient(`ws://127.0.0.1:${port}`, {
      wsOptions: {
        headers: {
          "x-api-key": "aegis-secret-key"
        }
      },
      reconnect: false
    });

    try {
      const unauthorizedClose = withTimeout(
        new Promise<{ code: number; reason: string }>((resolve) => {
          unauthorizedSocket.on("close", (code, reason) => {
            resolve({
              code,
              reason: reason.toString("utf8")
            });
          });
        }),
        TEST_TIMEOUT_MS,
        "unauthorized close"
      );

      const serverReadyClientPromise = withTimeout(
        new Promise<{
          id: string;
          metadata: ReadonlyMap<string, unknown>;
        }>((resolve) => {
          server.on("ready", (socket) => {
            resolve({
              id: socket.id,
              metadata: socket.metadata
            });
          });
        }),
        TEST_TIMEOUT_MS,
        "authorized server ready"
      );

      const authorizedReadyPromise = withTimeout(
        new Promise<void>((resolve) => {
          authorizedClient.on("ready", () => {
            resolve();
          });
        }),
        TEST_TIMEOUT_MS,
        "authorized client ready"
      );

      const [deniedConnection, serverReadyClient] = await Promise.all([
        unauthorizedClose,
        serverReadyClientPromise,
        authorizedReadyPromise
      ]);

      expect(deniedConnection.code).toBe(1008);
      expect(deniedConnection.reason).toMatch(/unauthorized api key/i);
      expect(unauthorizedErrorObserved).toBe(true);
      expect(serverReadyClient.id.length).toBeGreaterThan(0);
      expect(serverReadyClient.metadata.get("auth.subject")).toBe("integration-user");
    } finally {
      unauthorizedSocket.removeAllListeners();
      unauthorizedSocket.close();
      authorizedClient.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("runs incoming/outgoing middleware hooks and blocks disallowed events", async () => {
    const port = await getFreePort();
    const server = new SecureServer({ port, host: "127.0.0.1" });
    const client = new SecureClient(`ws://127.0.0.1:${port}`, {
      reconnect: false
    });

    let blockedHandlerTriggered = false;

    server.use(async (context, next) => {
      if (context.phase === "incoming") {
        if (context.event === "message:blocked") {
          throw new Error("Blocked by incoming middleware");
        }

        if (context.event === "message:echo") {
          const payload = context.data as { value: string };
          context.data = {
            ...payload,
            value: payload.value.toUpperCase(),
            inbound: true
          };
        }
      }

      if (context.phase === "outgoing" && context.event === "message:echo:ack") {
        const payload = context.data as {
          value: string;
          inbound: boolean;
        };

        context.data = {
          ...payload,
          outbound: true
        };
      }

      await next();
    });

    server.on("message:echo", (payload, socket) => {
      socket.emit("message:echo:ack", payload);
    });

    server.on("message:blocked", () => {
      blockedHandlerTriggered = true;
    });

    try {
      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready for middleware hook test"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for middleware hook test"
        )
      ]);

      const ackPromise = withTimeout(
        new Promise<unknown>((resolve) => {
          client.on("message:echo:ack", (payload) => {
            resolve(payload);
          });
        }),
        TEST_TIMEOUT_MS,
        "middleware-transformed ACK"
      );

      expect(client.emit("message:echo", { value: "hello" })).toBe(true);
      expect(client.emit("message:blocked", { value: "forbidden" })).toBe(true);

      const ackPayload = await ackPromise;

      expect(ackPayload).toEqual({
        value: "HELLO",
        inbound: true,
        outbound: true
      });

      await wait(100);
      expect(blockedHandlerTriggered).toBe(false);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("throttles burst traffic and drops messages while throttle window is active", async () => {
    const port = await getFreePort();
    const server = new SecureServer({
      port,
      host: "127.0.0.1",
      rateLimit: {
        enabled: true,
        windowMs: 1_000,
        maxEventsPerConnection: 1,
        maxEventsPerIp: 2,
        action: "throttle",
        throttleMs: 80,
        maxThrottleMs: 80,
        disconnectAfterViolations: 10
      }
    });
    const client = new SecureClient(`ws://127.0.0.1:${port}`, {
      reconnect: false
    });

    const processedEvents: number[] = [];

    server.on("burst:probe", (payload) => {
      const parsedPayload = payload as { sequence: number };
      processedEvents.push(parsedPayload.sequence);
    });

    try {
      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready for throttle test"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for throttle test"
        )
      ]);

      expect(client.emit("burst:probe", { sequence: 1 })).toBe(true);
      expect(client.emit("burst:probe", { sequence: 2 })).toBe(true);
      expect(client.emit("burst:probe", { sequence: 3 })).toBe(true);

      await wait(250);

      expect(processedEvents.length).toBeGreaterThanOrEqual(1);
      expect(processedEvents.length).toBeLessThanOrEqual(2);
      expect(processedEvents[0]).toBe(1);
      expect(processedEvents).not.toContain(3);
      expect(client.isConnected()).toBe(true);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });

  it("disconnects flooded clients when rate limiter action is set to disconnect", async () => {
    const port = await getFreePort();
    const server = new SecureServer({
      port,
      host: "127.0.0.1",
      rateLimit: {
        enabled: true,
        windowMs: 1_000,
        maxEventsPerConnection: 1,
        maxEventsPerIp: 1,
        action: "disconnect",
        disconnectAfterViolations: 1,
        disconnectCode: 1013,
        disconnectReason: "Rate limit exceeded. Please retry later."
      }
    });
    const client = new SecureClient(`ws://127.0.0.1:${port}`, {
      reconnect: false
    });

    server.on("burst:disconnect", () => {
      return undefined;
    });

    try {
      await Promise.all([
        withTimeout(
          new Promise<void>((resolve) => {
            server.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "server ready for disconnect throttle test"
        ),
        withTimeout(
          new Promise<void>((resolve) => {
            client.on("ready", () => {
              resolve();
            });
          }),
          TEST_TIMEOUT_MS,
          "client ready for disconnect throttle test"
        )
      ]);

      const disconnectPromise = withTimeout(
        new Promise<{ code: number; reason: string }>((resolve) => {
          client.on("disconnect", (code, reason) => {
            resolve({ code, reason });
          });
        }),
        TEST_TIMEOUT_MS,
        "disconnect after rate limit"
      );

      expect(client.emit("burst:disconnect", { step: 1 })).toBe(true);
      expect(client.emit("burst:disconnect", { step: 2 })).toBe(true);

      const disconnectPayload = await disconnectPromise;

      expect(disconnectPayload.code).toBe(1013);
      expect(disconnectPayload.reason).toMatch(/rate limit exceeded/i);

      await wait(50);
      expect(server.clientCount).toBe(0);
    } finally {
      client.disconnect();
      server.close();
      await wait(30);
    }
  });
});
