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
});
