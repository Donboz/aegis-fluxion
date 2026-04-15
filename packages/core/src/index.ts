import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  randomBytes,
  randomUUID
} from "node:crypto";
import type { ECDH } from "node:crypto";
import type { IncomingMessage } from "node:http";
import WebSocket, { WebSocketServer } from "ws";
import type {
  ClientOptions,
  RawData,
  ServerOptions as WebSocketServerOptions
} from "ws";

const DEFAULT_CLOSE_CODE = 1000;
const DEFAULT_CLOSE_REASON = "";
const INTERNAL_HANDSHAKE_EVENT = "__handshake";
const INTERNAL_RPC_REQUEST_EVENT = "__rpc:req";
const INTERNAL_RPC_RESPONSE_EVENT = "__rpc:res";
const READY_EVENT = "ready";
const HANDSHAKE_CURVE = "prime256v1";
const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const GCM_IV_LENGTH = 12;
const GCM_AUTH_TAG_LENGTH = 16;
const ENCRYPTION_KEY_LENGTH = 32;
const ENCRYPTED_PACKET_VERSION = 1;
const ENCRYPTED_PACKET_PREFIX_LENGTH = 1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;
const BINARY_PAYLOAD_MARKER = "__afxBinaryPayload";
const BINARY_PAYLOAD_VERSION = 1;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 15_000;
const DEFAULT_HEARTBEAT_TIMEOUT_MS = 15_000;
const DEFAULT_RECONNECT_INITIAL_DELAY_MS = 250;
const DEFAULT_RECONNECT_MAX_DELAY_MS = 10_000;
const DEFAULT_RECONNECT_FACTOR = 2;
const DEFAULT_RECONNECT_JITTER_RATIO = 0.2;
const DEFAULT_RPC_TIMEOUT_MS = 5_000;

interface HandshakePayload {
  publicKey: string;
}

interface ServerHandshakeState {
  ecdh: ECDH;
  localPublicKey: string;
  isReady: boolean;
}

interface ClientHandshakeState {
  ecdh: ECDH;
  localPublicKey: string;
  isReady: boolean;
  sharedSecret: Buffer | null;
  encryptionKey: Buffer | null;
}

interface EncryptedPacketParts {
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
}

interface RpcRequestPayload {
  id: string;
  event: string;
  data: unknown;
}

interface RpcResponsePayload {
  id: string;
  ok: boolean;
  data?: unknown;
  error?: string;
}

interface PendingRpcRequest {
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
  timeoutHandle: ReturnType<typeof setTimeout>;
}

type BinaryPayloadKind = "buffer" | "uint8array" | "blob";

interface EncodedBinaryPayload {
  [BINARY_PAYLOAD_MARKER]: number;
  kind: BinaryPayloadKind;
  base64: string;
  mimeType?: string;
}

export interface SecureEnvelope<TData = unknown> {
  event: string;
  data: TData;
}

export type SecureBinaryPayload = Buffer | Uint8Array | Blob;

export interface SecureAckOptions {
  timeoutMs?: number;
}

export type SecureAckCallback = (
  error: Error | null,
  response?: unknown
) => void;

export interface SecureServerHeartbeatOptions {
  enabled?: boolean;
  intervalMs?: number;
  timeoutMs?: number;
}

export interface SecureServerOptions extends WebSocketServerOptions {
  heartbeat?: SecureServerHeartbeatOptions;
}

export interface SecureClientReconnectOptions {
  enabled?: boolean;
  initialDelayMs?: number;
  maxDelayMs?: number;
  factor?: number;
  jitterRatio?: number;
  maxAttempts?: number | null;
}

export interface SecureClientOptions {
  protocols?: string | string[];
  wsOptions?: ClientOptions;
  autoConnect?: boolean;
  reconnect?: boolean | SecureClientReconnectOptions;
}

export interface SecureServerClient {
  id: string;
  socket: WebSocket;
  request: IncomingMessage;
  emit: (
    event: string,
    data: unknown,
    callbackOrOptions?: SecureAckCallback | SecureAckOptions,
    maybeCallback?: SecureAckCallback
  ) => boolean | Promise<unknown>;
  join: (room: string) => boolean;
  leave: (room: string) => boolean;
  leaveAll: () => number;
}

export interface SecureServerRoomOperator {
  emit: (event: string, data: unknown) => SecureServer;
}

export type SecureErrorHandler = (error: Error) => void;

export type SecureServerEventHandler = (
  data: unknown,
  client: SecureServerClient
) => unknown | Promise<unknown>;

export type SecureServerConnectionHandler = (
  client: SecureServerClient
) => void;

export type SecureServerDisconnectHandler = (
  client: SecureServerClient,
  code: number,
  reason: string
) => void;

export type SecureServerReadyHandler = (client: SecureServerClient) => void;

export type SecureClientEventHandler = (data: unknown) => unknown | Promise<unknown>;

export type SecureClientConnectHandler = () => void;

export type SecureClientDisconnectHandler = (
  code: number,
  reason: string
) => void;

export type SecureClientReadyHandler = () => void;

export type SecureServerLifecycleEvent =
  | "connection"
  | "disconnect"
  | "ready"
  | "error";

export type SecureClientLifecycleEvent =
  | "connect"
  | "disconnect"
  | "ready"
  | "error";

export interface SecureServerEventMap {
  connection: SecureServerConnectionHandler;
  disconnect: SecureServerDisconnectHandler;
  ready: SecureServerReadyHandler;
  error: SecureErrorHandler;
}

export interface SecureClientEventMap {
  connect: SecureClientConnectHandler;
  disconnect: SecureClientDisconnectHandler;
  ready: SecureClientReadyHandler;
  error: SecureErrorHandler;
}

function normalizeToError(error: unknown, fallbackMessage: string): Error {
  if (error instanceof Error) {
    return error;
  }

  if (typeof error === "string" && error.trim().length > 0) {
    return new Error(error);
  }

  return new Error(fallbackMessage);
}

function decodeRawData(rawData: RawData): string {
  if (typeof rawData === "string") {
    return rawData;
  }

  if (rawData instanceof ArrayBuffer) {
    return Buffer.from(rawData).toString("utf8");
  }

  if (Array.isArray(rawData)) {
    return Buffer.concat(rawData).toString("utf8");
  }

  return rawData.toString("utf8");
}

function rawDataToBuffer(rawData: RawData): Buffer {
  if (typeof rawData === "string") {
    return Buffer.from(rawData, "utf8");
  }

  if (rawData instanceof ArrayBuffer) {
    return Buffer.from(rawData);
  }

  if (Array.isArray(rawData)) {
    return Buffer.concat(rawData);
  }

  return Buffer.from(rawData);
}

function isBlobValue(value: unknown): value is Blob {
  return typeof Blob !== "undefined" && value instanceof Blob;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function encodeBinaryPayload(
  kind: BinaryPayloadKind,
  payloadBuffer: Buffer,
  mimeType?: string
): EncodedBinaryPayload {
  const encodedPayload: EncodedBinaryPayload = {
    [BINARY_PAYLOAD_MARKER]: BINARY_PAYLOAD_VERSION,
    kind,
    base64: payloadBuffer.toString("base64")
  };

  if (mimeType !== undefined && mimeType.length > 0) {
    encodedPayload.mimeType = mimeType;
  }

  return encodedPayload;
}

async function encodeEnvelopeData(value: unknown): Promise<unknown> {
  if (Buffer.isBuffer(value)) {
    return encodeBinaryPayload("buffer", value);
  }

  if (value instanceof Uint8Array) {
    const typedArrayBuffer = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    return encodeBinaryPayload("uint8array", typedArrayBuffer);
  }

  if (isBlobValue(value)) {
    const blobBuffer = Buffer.from(await value.arrayBuffer());
    return encodeBinaryPayload("blob", blobBuffer, value.type);
  }

  if (Array.isArray(value)) {
    return Promise.all(value.map((item) => encodeEnvelopeData(item)));
  }

  if (isPlainObject(value)) {
    const encodedEntries = await Promise.all(
      Object.entries(value).map(async ([key, entryValue]) => {
        return [key, await encodeEnvelopeData(entryValue)] as const;
      })
    );

    return Object.fromEntries(encodedEntries);
  }

  return value;
}

function isEncodedBinaryPayload(value: unknown): value is EncodedBinaryPayload {
  if (!isPlainObject(value)) {
    return false;
  }

  if (value[BINARY_PAYLOAD_MARKER] !== BINARY_PAYLOAD_VERSION) {
    return false;
  }

  if (
    value.kind !== "buffer" &&
    value.kind !== "uint8array" &&
    value.kind !== "blob"
  ) {
    return false;
  }

  if (typeof value.base64 !== "string") {
    return false;
  }

  if (value.mimeType !== undefined && typeof value.mimeType !== "string") {
    return false;
  }

  return true;
}

function decodeEnvelopeData(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => decodeEnvelopeData(item));
  }

  if (isEncodedBinaryPayload(value)) {
    const binaryBuffer = Buffer.from(value.base64, "base64");

    if (value.kind === "buffer") {
      return binaryBuffer;
    }

    if (value.kind === "uint8array") {
      return Uint8Array.from(binaryBuffer);
    }

    if (typeof Blob === "undefined") {
      return binaryBuffer;
    }

    return new Blob([binaryBuffer], {
      type: value.mimeType ?? ""
    });
  }

  if (isPlainObject(value)) {
    const decodedEntries = Object.entries(value).map(([key, entryValue]) => {
      return [key, decodeEnvelopeData(entryValue)] as const;
    });

    return Object.fromEntries(decodedEntries);
  }

  return value;
}

async function serializeEnvelope(event: string, data: unknown): Promise<string> {
  const encodedData = await encodeEnvelopeData(data);
  const envelope: SecureEnvelope = { event, data: encodedData };
  return JSON.stringify(envelope);
}

function serializePlainEnvelope(event: string, data: unknown): string {
  const envelope: SecureEnvelope = { event, data };
  return JSON.stringify(envelope);
}

function parseEnvelope(rawData: RawData): SecureEnvelope {
  const decoded = decodeRawData(rawData);
  const parsed = JSON.parse(decoded) as Partial<SecureEnvelope>;

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof parsed.event !== "string"
  ) {
    throw new Error("Invalid message format. Expected { event: string, data: unknown }.");
  }

  return {
    event: parsed.event,
    data: decodeEnvelopeData(parsed.data)
  };
}

function parseEnvelopeFromText(decodedPayload: string): SecureEnvelope {
  const parsed = JSON.parse(decodedPayload) as Partial<SecureEnvelope>;

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof parsed.event !== "string"
  ) {
    throw new Error("Invalid message format. Expected { event: string, data: unknown }.");
  }

  return {
    event: parsed.event,
    data: decodeEnvelopeData(parsed.data)
  };
}

function decodeCloseReason(reason: Buffer): string {
  return reason.toString("utf8");
}

function isReservedEmitEvent(event: string): boolean {
  return (
    event === INTERNAL_HANDSHAKE_EVENT ||
    event === INTERNAL_RPC_REQUEST_EVENT ||
    event === INTERNAL_RPC_RESPONSE_EVENT ||
    event === READY_EVENT
  );
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && "then" in value;
}

function normalizeRpcTimeout(timeoutMs: number | undefined): number {
  const resolvedTimeoutMs = timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;

  if (!Number.isFinite(resolvedTimeoutMs) || resolvedTimeoutMs <= 0) {
    throw new Error("ACK timeoutMs must be a positive number.");
  }

  return resolvedTimeoutMs;
}

function parseRpcRequestPayload(data: unknown): RpcRequestPayload {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid RPC request payload format.");
  }

  const payload = data as Partial<RpcRequestPayload>;

  if (typeof payload.id !== "string" || payload.id.trim().length === 0) {
    throw new Error("RPC request payload must include a non-empty id.");
  }

  if (typeof payload.event !== "string" || payload.event.trim().length === 0) {
    throw new Error("RPC request payload must include a non-empty event.");
  }

  return {
    id: payload.id,
    event: payload.event,
    data: payload.data
  };
}

function parseRpcResponsePayload(data: unknown): RpcResponsePayload {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid RPC response payload format.");
  }

  const payload = data as Partial<RpcResponsePayload>;

  if (typeof payload.id !== "string" || payload.id.trim().length === 0) {
    throw new Error("RPC response payload must include a non-empty id.");
  }

  if (typeof payload.ok !== "boolean") {
    throw new Error("RPC response payload must include a boolean ok field.");
  }

  if (payload.error !== undefined && typeof payload.error !== "string") {
    throw new Error("RPC response payload error must be a string when provided.");
  }

  const parsedPayload: RpcResponsePayload = {
    id: payload.id,
    ok: payload.ok,
    data: payload.data
  };

  if (payload.error !== undefined) {
    parsedPayload.error = payload.error;
  }

  return parsedPayload;
}

function resolveAckArguments(
  callbackOrOptions?: SecureAckCallback | SecureAckOptions,
  maybeCallback?: SecureAckCallback
): {
  expectsAck: boolean;
  callback?: SecureAckCallback;
  timeoutMs: number;
} {
  if (callbackOrOptions === undefined && maybeCallback === undefined) {
    return {
      expectsAck: false,
      timeoutMs: DEFAULT_RPC_TIMEOUT_MS
    };
  }

  if (typeof callbackOrOptions === "function") {
    if (maybeCallback !== undefined) {
      throw new Error("ACK callback was provided more than once.");
    }

    return {
      expectsAck: true,
      callback: callbackOrOptions,
      timeoutMs: DEFAULT_RPC_TIMEOUT_MS
    };
  }

  const options = callbackOrOptions;

  if (options !== undefined && (typeof options !== "object" || options === null)) {
    throw new Error("ACK options must be an object.");
  }

  if (maybeCallback !== undefined && typeof maybeCallback !== "function") {
    throw new Error("ACK callback must be a function.");
  }

  return {
    ...(maybeCallback ? { callback: maybeCallback } : {}),
    expectsAck: true,
    timeoutMs: normalizeRpcTimeout(options?.timeoutMs)
  };
}

function createEphemeralHandshakeState(): { ecdh: ECDH; localPublicKey: string } {
  const ecdh = createECDH(HANDSHAKE_CURVE);
  ecdh.generateKeys();

  return {
    ecdh,
    localPublicKey: ecdh.getPublicKey("base64")
  };
}

function parseHandshakePayload(data: unknown): HandshakePayload {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid handshake payload format.");
  }

  const payload = data as Partial<HandshakePayload>;

  if (typeof payload.publicKey !== "string" || payload.publicKey.length === 0) {
    throw new Error("Handshake payload must include a non-empty public key.");
  }

  return {
    publicKey: payload.publicKey
  };
}

function deriveEncryptionKey(sharedSecret: Buffer): Buffer {
  const derivedKey = createHash("sha256").update(sharedSecret).digest();

  if (derivedKey.length !== ENCRYPTION_KEY_LENGTH) {
    throw new Error("Failed to derive a valid AES-256 key.");
  }

  return derivedKey;
}

function encryptSerializedEnvelope(serializedEnvelope: string, encryptionKey: Buffer): Buffer {
  const iv = randomBytes(GCM_IV_LENGTH);
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(serializedEnvelope, "utf8"),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([
    Buffer.from([ENCRYPTED_PACKET_VERSION]),
    iv,
    authTag,
    ciphertext
  ]);
}

function parseEncryptedPacket(rawData: RawData): EncryptedPacketParts {
  const packetBuffer = rawDataToBuffer(rawData);

  if (packetBuffer.length <= ENCRYPTED_PACKET_PREFIX_LENGTH) {
    throw new Error("Encrypted packet is too short.");
  }

  const version = packetBuffer.readUInt8(0);

  if (version !== ENCRYPTED_PACKET_VERSION) {
    throw new Error("Unsupported encrypted packet version.");
  }

  const ivStart = 1;
  const ivEnd = ivStart + GCM_IV_LENGTH;
  const authTagStart = ivEnd;
  const authTagEnd = authTagStart + GCM_AUTH_TAG_LENGTH;

  const iv = packetBuffer.subarray(ivStart, ivEnd);
  const authTag = packetBuffer.subarray(authTagStart, authTagEnd);
  const ciphertext = packetBuffer.subarray(authTagEnd);

  if (ciphertext.length === 0) {
    throw new Error("Encrypted payload is empty.");
  }

  return {
    iv,
    authTag,
    ciphertext
  };
}

function decryptSerializedEnvelope(rawData: RawData, encryptionKey: Buffer): string {
  const encryptedPacket = parseEncryptedPacket(rawData);
  const decipher = createDecipheriv(
    ENCRYPTION_ALGORITHM,
    encryptionKey,
    encryptedPacket.iv
  );

  decipher.setAuthTag(encryptedPacket.authTag);

  const plaintext = Buffer.concat([
    decipher.update(encryptedPacket.ciphertext),
    decipher.final()
  ]);

  return plaintext.toString("utf8");
}

export class SecureServer {
  private readonly socketServer: WebSocketServer;

  private readonly heartbeatConfig: Required<SecureServerHeartbeatOptions>;

  private heartbeatIntervalHandle: ReturnType<typeof setInterval> | null = null;

  private readonly clientsById = new Map<string, SecureServerClient>();

  private readonly clientIdBySocket = new Map<WebSocket, string>();

  private readonly customEventHandlers = new Map<string, Set<SecureServerEventHandler>>();

  private readonly connectionHandlers = new Set<SecureServerConnectionHandler>();

  private readonly disconnectHandlers = new Set<SecureServerDisconnectHandler>();

  private readonly readyHandlers = new Set<SecureServerReadyHandler>();

  private readonly errorHandlers = new Set<SecureErrorHandler>();

  private readonly handshakeStateBySocket = new WeakMap<WebSocket, ServerHandshakeState>();

  private readonly sharedSecretBySocket = new WeakMap<WebSocket, Buffer>();

  private readonly encryptionKeyBySocket = new WeakMap<WebSocket, Buffer>();

  private readonly pendingPayloadsBySocket = new WeakMap<WebSocket, SecureEnvelope[]>();

  private readonly pendingRpcRequestsBySocket = new WeakMap<
    WebSocket,
    Map<string, PendingRpcRequest>
  >();

  private readonly heartbeatStateBySocket = new WeakMap<
    WebSocket,
    { awaitingPong: boolean; lastPingAt: number }
  >();

  private readonly roomMembersByName = new Map<string, Set<string>>();

  private readonly roomNamesByClientId = new Map<string, Set<string>>();

  public constructor(options: SecureServerOptions) {
    const { heartbeat, ...socketServerOptions } = options;

    this.heartbeatConfig = this.resolveHeartbeatConfig(heartbeat);
    this.socketServer = new WebSocketServer(socketServerOptions);
    this.bindSocketServerEvents();
    this.startHeartbeatLoop();
  }

  public get clientCount(): number {
    return this.clientsById.size;
  }

  public get clients(): ReadonlyMap<string, SecureServerClient> {
    return this.clientsById;
  }

  public on(event: "connection", handler: SecureServerConnectionHandler): this;
  public on(event: "disconnect", handler: SecureServerDisconnectHandler): this;
  public on(event: "ready", handler: SecureServerReadyHandler): this;
  public on(event: "error", handler: SecureErrorHandler): this;
  public on(event: string, handler: SecureServerEventHandler): this;
  public on(event: string, handler: unknown): this {
    try {
      if (event === "connection") {
        this.connectionHandlers.add(handler as SecureServerConnectionHandler);
        return this;
      }

      if (event === "disconnect") {
        this.disconnectHandlers.add(handler as SecureServerDisconnectHandler);
        return this;
      }

      if (event === READY_EVENT) {
        this.readyHandlers.add(handler as SecureServerReadyHandler);
        return this;
      }

      if (event === "error") {
        this.errorHandlers.add(handler as SecureErrorHandler);
        return this;
      }

      if (event === INTERNAL_HANDSHAKE_EVENT) {
        throw new Error(`The event "${INTERNAL_HANDSHAKE_EVENT}" is reserved for internal use.`);
      }

      const typedHandler = handler as SecureServerEventHandler;
      const listeners = this.customEventHandlers.get(event) ?? new Set<SecureServerEventHandler>();
      listeners.add(typedHandler);
      this.customEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register server event handler.")
      );
    }

    return this;
  }

  public off(event: "connection", handler: SecureServerConnectionHandler): this;
  public off(event: "disconnect", handler: SecureServerDisconnectHandler): this;
  public off(event: "ready", handler: SecureServerReadyHandler): this;
  public off(event: "error", handler: SecureErrorHandler): this;
  public off(event: string, handler: SecureServerEventHandler): this;
  public off(event: string, handler: unknown): this {
    try {
      if (event === "connection") {
        this.connectionHandlers.delete(handler as SecureServerConnectionHandler);
        return this;
      }

      if (event === "disconnect") {
        this.disconnectHandlers.delete(handler as SecureServerDisconnectHandler);
        return this;
      }

      if (event === READY_EVENT) {
        this.readyHandlers.delete(handler as SecureServerReadyHandler);
        return this;
      }

      if (event === "error") {
        this.errorHandlers.delete(handler as SecureErrorHandler);
        return this;
      }

      if (event === INTERNAL_HANDSHAKE_EVENT) {
        return this;
      }

      const listeners = this.customEventHandlers.get(event);

      if (!listeners) {
        return this;
      }

      listeners.delete(handler as SecureServerEventHandler);

      if (listeners.size === 0) {
        this.customEventHandlers.delete(event);
      }
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to remove server event handler.")
      );
    }

    return this;
  }

  public emit(event: string, data: unknown): this {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      const envelope: SecureEnvelope = { event, data };

      for (const client of this.clientsById.values()) {
        void this.sendOrQueuePayload(client.socket, envelope).catch(() => {
          return undefined;
        });
      }
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to emit server event."));
    }

    return this;
  }

  public emitTo(clientId: string, event: string, data: unknown): boolean;
  public emitTo(
    clientId: string,
    event: string,
    data: unknown,
    callback: SecureAckCallback
  ): boolean;
  public emitTo(
    clientId: string,
    event: string,
    data: unknown,
    options: SecureAckOptions
  ): Promise<unknown>;
  public emitTo(
    clientId: string,
    event: string,
    data: unknown,
    options: SecureAckOptions,
    callback: SecureAckCallback
  ): boolean;
  public emitTo(
    clientId: string,
    event: string,
    data: unknown,
    callbackOrOptions?: SecureAckCallback | SecureAckOptions,
    maybeCallback?: SecureAckCallback
  ): boolean | Promise<unknown> {
    const ackArgs = resolveAckArguments(callbackOrOptions, maybeCallback);

    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      const client = this.clientsById.get(clientId);

      if (!client) {
        throw new Error(`Client with id ${clientId} was not found.`);
      }

      if (!ackArgs.expectsAck) {
        void this.sendOrQueuePayload(client.socket, { event, data }).catch(() => {
          return undefined;
        });
        return true;
      }

      const ackPromise = this.sendRpcRequest(
        client.socket,
        event,
        data,
        ackArgs.timeoutMs
      );

      if (ackArgs.callback) {
        ackPromise
          .then((response) => {
            ackArgs.callback?.(null, response);
          })
          .catch((error) => {
            ackArgs.callback?.(
              normalizeToError(error, `ACK callback failed for client ${client.id}.`)
            );
          });

        return true;
      }

      return ackPromise;
    } catch (error) {
      const normalizedError = normalizeToError(error, "Failed to emit event to client.");
      this.notifyError(normalizedError);

      if (ackArgs.callback) {
        ackArgs.callback(normalizedError);
        return false;
      }

      if (ackArgs.expectsAck) {
        return Promise.reject(normalizedError);
      }

      return false;
    }
  }

  public to(room: string): SecureServerRoomOperator {
    const normalizedRoom = this.normalizeRoomName(room);

    return {
      emit: (event: string, data: unknown): SecureServer => {
        try {
          this.emitToRoom(normalizedRoom, event, data);
        } catch (error) {
          this.notifyError(
            normalizeToError(error, `Failed to emit event to room ${normalizedRoom}.`)
          );
        }

        return this;
      }
    };
  }

  public close(
    code: number = DEFAULT_CLOSE_CODE,
    reason: string = DEFAULT_CLOSE_REASON
  ): void {
    try {
      this.stopHeartbeatLoop();

      for (const client of this.clientsById.values()) {
        this.rejectPendingRpcRequests(
          client.socket,
          new Error("Server closed before ACK response was received.")
        );

        if (
          client.socket.readyState === WebSocket.OPEN ||
          client.socket.readyState === WebSocket.CONNECTING
        ) {
          client.socket.close(code, reason);
        }
      }

      this.socketServer.close();
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to close server."));
    }
  }

  private resolveHeartbeatConfig(
    heartbeatOptions: SecureServerHeartbeatOptions | undefined
  ): Required<SecureServerHeartbeatOptions> {
    const intervalMs = heartbeatOptions?.intervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
    const timeoutMs = heartbeatOptions?.timeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;

    if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new Error("Server heartbeat intervalMs must be a positive number.");
    }

    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new Error("Server heartbeat timeoutMs must be a positive number.");
    }

    return {
      enabled: heartbeatOptions?.enabled ?? true,
      intervalMs,
      timeoutMs
    };
  }

  private startHeartbeatLoop(): void {
    if (!this.heartbeatConfig.enabled || this.heartbeatIntervalHandle) {
      return;
    }

    this.heartbeatIntervalHandle = setInterval(() => {
      this.performHeartbeatSweep();
    }, this.heartbeatConfig.intervalMs);

    this.heartbeatIntervalHandle.unref?.();
  }

  private stopHeartbeatLoop(): void {
    if (!this.heartbeatIntervalHandle) {
      return;
    }

    clearInterval(this.heartbeatIntervalHandle);
    this.heartbeatIntervalHandle = null;
  }

  private performHeartbeatSweep(): void {
    const now = Date.now();

    for (const client of this.clientsById.values()) {
      const socket = client.socket;

      if (socket.readyState !== WebSocket.OPEN) {
        continue;
      }

      const heartbeatState = this.heartbeatStateBySocket.get(socket) ?? {
        awaitingPong: false,
        lastPingAt: 0
      };

      if (
        heartbeatState.awaitingPong &&
        now - heartbeatState.lastPingAt >= this.heartbeatConfig.timeoutMs
      ) {
        this.rejectPendingRpcRequests(
          socket,
          new Error(`Heartbeat timeout while waiting for client ${client.id} ACK response.`)
        );
        this.sharedSecretBySocket.delete(socket);
        this.encryptionKeyBySocket.delete(socket);
        this.pendingPayloadsBySocket.delete(socket);
        this.pendingRpcRequestsBySocket.delete(socket);
        this.handshakeStateBySocket.delete(socket);
        this.heartbeatStateBySocket.delete(socket);
        socket.terminate();
        continue;
      }

      if (heartbeatState.awaitingPong) {
        continue;
      }

      heartbeatState.awaitingPong = true;
      heartbeatState.lastPingAt = now;
      this.heartbeatStateBySocket.set(socket, heartbeatState);

      try {
        socket.ping();
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Failed to send heartbeat ping to client ${client.id}.`)
        );
      }
    }
  }

  private handleHeartbeatPong(socket: WebSocket): void {
    const heartbeatState = this.heartbeatStateBySocket.get(socket);

    if (!heartbeatState) {
      return;
    }

    heartbeatState.awaitingPong = false;
    heartbeatState.lastPingAt = 0;
    this.heartbeatStateBySocket.set(socket, heartbeatState);
  }

  private bindSocketServerEvents(): void {
    this.socketServer.on("connection", (socket: WebSocket, request: IncomingMessage) => {
      this.handleConnection(socket, request);
    });

    this.socketServer.on("error", (error: Error) => {
      this.notifyError(normalizeToError(error, "WebSocket server encountered an error."));
    });
  }

  private handleConnection(socket: WebSocket, request: IncomingMessage): void {
    try {
      const clientId = randomUUID();
      const handshakeState = this.createServerHandshakeState();
      const client = this.createSecureServerClient(clientId, socket, request);

      this.clientsById.set(clientId, client);
      this.clientIdBySocket.set(socket, clientId);
      this.handshakeStateBySocket.set(socket, handshakeState);
      this.pendingPayloadsBySocket.set(socket, []);
      this.pendingRpcRequestsBySocket.set(socket, new Map<string, PendingRpcRequest>());
      this.heartbeatStateBySocket.set(socket, {
        awaitingPong: false,
        lastPingAt: 0
      });
      this.roomNamesByClientId.set(clientId, new Set<string>());

      socket.on("message", (rawData: RawData) => {
        this.handleIncomingMessage(client, rawData);
      });

      socket.on("close", (code: number, reason: Buffer) => {
        this.handleDisconnection(client, code, reason);
      });

      socket.on("pong", () => {
        this.handleHeartbeatPong(client.socket);
      });

      socket.on("error", (error: Error) => {
        this.notifyError(
          normalizeToError(
            error,
            `Client socket error detected for client ${client.id}.`
          )
        );
      });

      this.sendInternalHandshake(socket, handshakeState.localPublicKey);
      this.notifyConnection(client);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to handle client connection."));
    }
  }

  private handleIncomingMessage(client: SecureServerClient, rawData: RawData): void {
    try {
      let envelope: SecureEnvelope | null = null;

      try {
        envelope = parseEnvelope(rawData);
      } catch {
        envelope = null;
      }

      if (envelope?.event === INTERNAL_HANDSHAKE_EVENT) {
        this.handleInternalHandshake(client, envelope.data);
        return;
      }

      if (envelope !== null) {
        this.notifyError(
          new Error(
            `Plaintext event "${envelope.event}" was rejected for client ${client.id}.`
          )
        );
        return;
      }

      if (!this.isClientHandshakeReady(client.socket)) {
        this.notifyError(
          new Error(`Encrypted payload was received before handshake completion for client ${client.id}.`)
        );
        return;
      }

      const encryptionKey = this.encryptionKeyBySocket.get(client.socket);

      if (!encryptionKey) {
        this.notifyError(new Error(`Missing encryption key for client ${client.id}.`));
        return;
      }

      let decryptedPayload: string;

      try {
        decryptedPayload = decryptSerializedEnvelope(rawData, encryptionKey);
      } catch {
        console.warn("Tampered data detected and dropped");
        return;
      }

      const decryptedEnvelope = parseEnvelopeFromText(decryptedPayload);

      if (decryptedEnvelope.event === INTERNAL_RPC_RESPONSE_EVENT) {
        this.handleRpcResponse(client.socket, decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_RPC_REQUEST_EVENT) {
        void this.handleRpcRequest(client, decryptedEnvelope.data);
        return;
      }

      this.dispatchCustomEvent(decryptedEnvelope.event, decryptedEnvelope.data, client);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process incoming server message."));
    }
  }

  private handleDisconnection(client: SecureServerClient, code: number, reason: Buffer): void {
    try {
      client.leaveAll();
      this.clientsById.delete(client.id);
      this.clientIdBySocket.delete(client.socket);
      this.handshakeStateBySocket.delete(client.socket);
      this.sharedSecretBySocket.delete(client.socket);
      this.encryptionKeyBySocket.delete(client.socket);
      this.pendingPayloadsBySocket.delete(client.socket);
      this.rejectPendingRpcRequests(
        client.socket,
        new Error(`Client ${client.id} disconnected before ACK response was received.`)
      );
      this.pendingRpcRequestsBySocket.delete(client.socket);
      this.heartbeatStateBySocket.delete(client.socket);

      const decodedReason = decodeCloseReason(reason);

      for (const handler of this.disconnectHandlers) {
        try {
          handler(client, code, decodedReason);
        } catch (handlerError) {
          this.notifyError(
            normalizeToError(
              handlerError,
              `Disconnect handler failed for client ${client.id}.`
            )
          );
        }
      }
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process client disconnection."));
    }
  }

  private dispatchCustomEvent(
    event: string,
    data: unknown,
    client: SecureServerClient
  ): void {
    const handlers = this.customEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      return;
    }

    for (const handler of handlers) {
      try {
        const handlerResult = handler(data, client);

        if (isPromiseLike(handlerResult)) {
          void Promise.resolve(handlerResult).catch((error) => {
            this.notifyError(
              normalizeToError(
                error,
                `Server event handler failed for event ${event}.`
              )
            );
          });
        }
      } catch (error) {
        this.notifyError(
          normalizeToError(
            error,
            `Server event handler failed for event ${event}.`
          )
        );
      }
    }
  }

  private sendRaw(socket: WebSocket, payload: string): void {
    try {
      if (socket.readyState !== WebSocket.OPEN) {
        return;
      }

      socket.send(payload);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send server payload."));
    }
  }

  private async sendEncryptedEnvelope(socket: WebSocket, envelope: SecureEnvelope): Promise<void> {
    if (socket.readyState !== WebSocket.OPEN) {
      return;
    }

    const encryptionKey = this.encryptionKeyBySocket.get(socket);

    if (!encryptionKey) {
      const missingKeyError = new Error("Missing encryption key for connected socket.");
      this.notifyError(missingKeyError);
      throw missingKeyError;
    }

    try {
      const serializedEnvelope = await serializeEnvelope(envelope.event, envelope.data);
      const encryptedPayload = encryptSerializedEnvelope(serializedEnvelope, encryptionKey);
      socket.send(encryptedPayload);
    } catch (error) {
      const normalizedError = normalizeToError(error, "Failed to send encrypted server payload.");
      this.notifyError(normalizedError);
      throw normalizedError;
    }
  }

  private sendRpcRequest(
    socket: WebSocket,
    event: string,
    data: unknown,
    timeoutMs: number
  ): Promise<unknown> {
    if (socket.readyState !== WebSocket.OPEN && socket.readyState !== WebSocket.CONNECTING) {
      throw new Error("Client socket is not connected for ACK request.");
    }

    const pendingRequests =
      this.pendingRpcRequestsBySocket.get(socket) ?? new Map<string, PendingRpcRequest>();
    this.pendingRpcRequestsBySocket.set(socket, pendingRequests);

    const requestId = randomUUID();

    return new Promise<unknown>((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        pendingRequests.delete(requestId);
        reject(new Error(`ACK response timed out after ${timeoutMs}ms for event "${event}".`));
      }, timeoutMs);

      timeoutHandle.unref?.();

      pendingRequests.set(requestId, {
        resolve,
        reject,
        timeoutHandle
      });

      void this.sendOrQueuePayload(socket, {
        event: INTERNAL_RPC_REQUEST_EVENT,
        data: {
          id: requestId,
          event,
          data
        } satisfies RpcRequestPayload
      }).catch((error) => {
        clearTimeout(timeoutHandle);
        pendingRequests.delete(requestId);
        reject(
          normalizeToError(error, `Failed to dispatch ACK request for event "${event}".`)
        );
      });
    });
  }

  private handleRpcResponse(socket: WebSocket, data: unknown): void {
    try {
      const responsePayload = parseRpcResponsePayload(data);
      const pendingRequests = this.pendingRpcRequestsBySocket.get(socket);

      if (!pendingRequests) {
        return;
      }

      const pendingRequest = pendingRequests.get(responsePayload.id);

      if (!pendingRequest) {
        return;
      }

      clearTimeout(pendingRequest.timeoutHandle);
      pendingRequests.delete(responsePayload.id);

      if (responsePayload.ok) {
        pendingRequest.resolve(responsePayload.data);
        return;
      }

      pendingRequest.reject(
        new Error(responsePayload.error ?? "ACK request failed without an error message.")
      );
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process server ACK response."));
    }
  }

  private async handleRpcRequest(client: SecureServerClient, data: unknown): Promise<void> {
    let rpcRequestPayload: RpcRequestPayload;

    try {
      rpcRequestPayload = parseRpcRequestPayload(data);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Invalid server ACK request payload."));
      return;
    }

    try {
      const ackResponse = await this.executeRpcRequestHandler(
        rpcRequestPayload.event,
        rpcRequestPayload.data,
        client
      );

      await this.sendEncryptedEnvelope(client.socket, {
        event: INTERNAL_RPC_RESPONSE_EVENT,
        data: {
          id: rpcRequestPayload.id,
          ok: true,
          data: ackResponse
        } satisfies RpcResponsePayload
      });
    } catch (error) {
      const normalizedError = normalizeToError(error, "Server ACK request handler failed.");

      await this.sendEncryptedEnvelope(client.socket, {
        event: INTERNAL_RPC_RESPONSE_EVENT,
        data: {
          id: rpcRequestPayload.id,
          ok: false,
          error: normalizedError.message
        } satisfies RpcResponsePayload
      });

      this.notifyError(normalizedError);
    }
  }

  private async executeRpcRequestHandler(
    event: string,
    data: unknown,
    client: SecureServerClient
  ): Promise<unknown> {
    const handlers = this.customEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      throw new Error(`No handler is registered for ACK request event "${event}".`);
    }

    const firstHandler = handlers.values().next().value as SecureServerEventHandler;
    return Promise.resolve(firstHandler(data, client));
  }

  private rejectPendingRpcRequests(socket: WebSocket, error: Error): void {
    const pendingRequests = this.pendingRpcRequestsBySocket.get(socket);

    if (!pendingRequests) {
      return;
    }

    for (const pendingRequest of pendingRequests.values()) {
      clearTimeout(pendingRequest.timeoutHandle);
      pendingRequest.reject(error);
    }

    pendingRequests.clear();
  }

  private notifyConnection(client: SecureServerClient): void {
    for (const handler of this.connectionHandlers) {
      try {
        handler(client);
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Connection handler failed for client ${client.id}.`)
        );
      }
    }
  }

  private notifyReady(client: SecureServerClient): void {
    for (const handler of this.readyHandlers) {
      try {
        handler(client);
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Ready handler failed for client ${client.id}.`)
        );
      }
    }
  }

  private notifyError(error: Error): void {
    if (this.errorHandlers.size === 0) {
      return;
    }

    for (const handler of this.errorHandlers) {
      try {
        handler(error);
      } catch {
        // Error handlers should not throw into the event loop.
      }
    }
  }

  private createServerHandshakeState(): ServerHandshakeState {
    const { ecdh, localPublicKey } = createEphemeralHandshakeState();

    return {
      ecdh,
      localPublicKey,
      isReady: false
    };
  }

  private sendInternalHandshake(socket: WebSocket, localPublicKey: string): void {
    this.sendRaw(
      socket,
      serializePlainEnvelope(INTERNAL_HANDSHAKE_EVENT, {
        publicKey: localPublicKey
      })
    );
  }

  private handleInternalHandshake(client: SecureServerClient, data: unknown): void {
    try {
      const payload = parseHandshakePayload(data);
      const handshakeState = this.handshakeStateBySocket.get(client.socket);

      if (!handshakeState) {
        throw new Error(`Missing handshake state for client ${client.id}.`);
      }

      if (handshakeState.isReady) {
        return;
      }

      const remotePublicKey = Buffer.from(payload.publicKey, "base64");
      const sharedSecret = handshakeState.ecdh.computeSecret(remotePublicKey);
      const encryptionKey = deriveEncryptionKey(sharedSecret);

      this.sharedSecretBySocket.set(client.socket, sharedSecret);
      this.encryptionKeyBySocket.set(client.socket, encryptionKey);
      handshakeState.isReady = true;

      this.flushQueuedPayloads(client.socket);
      this.notifyReady(client);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to complete server handshake."));
    }
  }

  private isClientHandshakeReady(socket: WebSocket): boolean {
    return this.handshakeStateBySocket.get(socket)?.isReady ?? false;
  }

  private sendOrQueuePayload(socket: WebSocket, envelope: SecureEnvelope): Promise<void> {
    if (!this.isClientHandshakeReady(socket)) {
      this.queuePayload(socket, envelope);
      return Promise.resolve();
    }

    return this.sendEncryptedEnvelope(socket, envelope);
  }

  private queuePayload(socket: WebSocket, envelope: SecureEnvelope): void {
    const pendingPayloads = this.pendingPayloadsBySocket.get(socket) ?? [];
    pendingPayloads.push(envelope);
    this.pendingPayloadsBySocket.set(socket, pendingPayloads);
  }

  private async flushQueuedPayloads(socket: WebSocket): Promise<void> {
    const pendingPayloads = this.pendingPayloadsBySocket.get(socket);

    if (!pendingPayloads || pendingPayloads.length === 0) {
      return;
    }

    this.pendingPayloadsBySocket.delete(socket);

    for (const envelope of pendingPayloads) {
      await this.sendEncryptedEnvelope(socket, envelope);
    }
  }

  private createSecureServerClient(
    clientId: string,
    socket: WebSocket,
    request: IncomingMessage
  ): SecureServerClient {
    return {
      id: clientId,
      socket,
      request,
      emit: (
        event: string,
        data: unknown,
        callbackOrOptions?: SecureAckCallback | SecureAckOptions,
        maybeCallback?: SecureAckCallback
      ): boolean | Promise<unknown> => {
        if (callbackOrOptions === undefined && maybeCallback === undefined) {
          return this.emitTo(clientId, event, data);
        }

        if (typeof callbackOrOptions === "function") {
          return this.emitTo(clientId, event, data, callbackOrOptions);
        }

        if (maybeCallback) {
          return this.emitTo(
            clientId,
            event,
            data,
            callbackOrOptions ?? {},
            maybeCallback
          );
        }

        return this.emitTo(clientId, event, data, callbackOrOptions ?? {});
      },
      join: (room: string): boolean => this.joinClientToRoom(clientId, room),
      leave: (room: string): boolean => this.leaveClientFromRoom(clientId, room),
      leaveAll: (): number => this.leaveClientFromAllRooms(clientId)
    };
  }

  private normalizeRoomName(room: string): string {
    if (typeof room !== "string") {
      throw new Error("Room name must be a string.");
    }

    const normalizedRoom = room.trim();

    if (normalizedRoom.length === 0) {
      throw new Error("Room name cannot be empty.");
    }

    return normalizedRoom;
  }

  private joinClientToRoom(clientId: string, room: string): boolean {
    const normalizedRoom = this.normalizeRoomName(room);

    if (!this.clientsById.has(clientId)) {
      return false;
    }

    const clientRooms = this.roomNamesByClientId.get(clientId) ?? new Set<string>();

    if (clientRooms.has(normalizedRoom)) {
      this.roomNamesByClientId.set(clientId, clientRooms);
      return false;
    }

    clientRooms.add(normalizedRoom);
    this.roomNamesByClientId.set(clientId, clientRooms);

    const roomMembers = this.roomMembersByName.get(normalizedRoom) ?? new Set<string>();
    roomMembers.add(clientId);
    this.roomMembersByName.set(normalizedRoom, roomMembers);

    return true;
  }

  private leaveClientFromRoom(clientId: string, room: string): boolean {
    const normalizedRoom = this.normalizeRoomName(room);
    const clientRooms = this.roomNamesByClientId.get(clientId);

    if (!clientRooms || !clientRooms.delete(normalizedRoom)) {
      return false;
    }

    if (clientRooms.size === 0) {
      this.roomNamesByClientId.delete(clientId);
    }

    const roomMembers = this.roomMembersByName.get(normalizedRoom);

    if (roomMembers) {
      roomMembers.delete(clientId);

      if (roomMembers.size === 0) {
        this.roomMembersByName.delete(normalizedRoom);
      }
    }

    return true;
  }

  private leaveClientFromAllRooms(clientId: string): number {
    const clientRooms = this.roomNamesByClientId.get(clientId);

    if (!clientRooms || clientRooms.size === 0) {
      this.roomNamesByClientId.delete(clientId);
      return 0;
    }

    const roomNames = [...clientRooms];
    this.roomNamesByClientId.delete(clientId);

    for (const roomName of roomNames) {
      const roomMembers = this.roomMembersByName.get(roomName);

      if (!roomMembers) {
        continue;
      }

      roomMembers.delete(clientId);

      if (roomMembers.size === 0) {
        this.roomMembersByName.delete(roomName);
      }
    }

    return roomNames.length;
  }

  private emitToRoom(room: string, event: string, data: unknown): void {
    if (isReservedEmitEvent(event)) {
      throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
    }

    const roomMembers = this.roomMembersByName.get(room);

    if (!roomMembers || roomMembers.size === 0) {
      return;
    }

    const envelope: SecureEnvelope = { event, data };

    for (const clientId of roomMembers) {
      const client = this.clientsById.get(clientId);

      if (!client) {
        continue;
      }

        void this.sendOrQueuePayload(client.socket, envelope).catch(() => {
          return undefined;
        });
    }
  }
}

export class SecureClient {
  private socket: WebSocket | null = null;

  private readonly reconnectConfig: Required<SecureClientReconnectOptions>;

  private reconnectAttemptCount = 0;

  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  private isManualDisconnectRequested = false;

  private readonly customEventHandlers = new Map<string, Set<SecureClientEventHandler>>();

  private readonly connectHandlers = new Set<SecureClientConnectHandler>();

  private readonly disconnectHandlers = new Set<SecureClientDisconnectHandler>();

  private readonly readyHandlers = new Set<SecureClientReadyHandler>();

  private readonly errorHandlers = new Set<SecureErrorHandler>();

  private handshakeState: ClientHandshakeState | null = null;

  private pendingPayloadQueue: SecureEnvelope[] = [];

  private readonly pendingRpcRequests = new Map<string, PendingRpcRequest>();

  public constructor(
    private readonly url: string,
    private readonly options: SecureClientOptions = {}
  ) {
    this.reconnectConfig = this.resolveReconnectConfig(this.options.reconnect);

    if (this.options.autoConnect ?? true) {
      this.connect();
    }
  }

  public get readyState(): number | null {
    return this.socket?.readyState ?? null;
  }

  public isConnected(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  public connect(): void {
    try {
      if (
        this.socket &&
        (this.socket.readyState === WebSocket.OPEN ||
          this.socket.readyState === WebSocket.CONNECTING)
      ) {
        return;
      }

      this.clearReconnectTimer();
      this.isManualDisconnectRequested = false;

      const socket = this.createSocket();
      this.socket = socket;
      this.handshakeState = this.createClientHandshakeState();
      this.pendingPayloadQueue = [];
      this.bindSocketEvents(socket);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to connect client."));

      if (!this.isManualDisconnectRequested) {
        this.scheduleReconnect();
      }
    }
  }

  public disconnect(
    code: number = DEFAULT_CLOSE_CODE,
    reason: string = DEFAULT_CLOSE_REASON
  ): void {
    try {
      this.isManualDisconnectRequested = true;
      this.clearReconnectTimer();

      if (!this.socket) {
        return;
      }

      if (
        this.socket.readyState === WebSocket.CLOSING ||
        this.socket.readyState === WebSocket.CLOSED
      ) {
        return;
      }

      this.socket.close(code, reason);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to disconnect client."));
    }
  }

  public on(event: "connect", handler: SecureClientConnectHandler): this;
  public on(event: "disconnect", handler: SecureClientDisconnectHandler): this;
  public on(event: "ready", handler: SecureClientReadyHandler): this;
  public on(event: "error", handler: SecureErrorHandler): this;
  public on(event: string, handler: SecureClientEventHandler): this;
  public on(event: string, handler: unknown): this {
    try {
      if (event === "connect") {
        this.connectHandlers.add(handler as SecureClientConnectHandler);
        return this;
      }

      if (event === "disconnect") {
        this.disconnectHandlers.add(handler as SecureClientDisconnectHandler);
        return this;
      }

      if (event === READY_EVENT) {
        this.readyHandlers.add(handler as SecureClientReadyHandler);
        return this;
      }

      if (event === "error") {
        this.errorHandlers.add(handler as SecureErrorHandler);
        return this;
      }

      if (event === INTERNAL_HANDSHAKE_EVENT) {
        throw new Error(`The event "${INTERNAL_HANDSHAKE_EVENT}" is reserved for internal use.`);
      }

      const typedHandler = handler as SecureClientEventHandler;
      const listeners = this.customEventHandlers.get(event) ?? new Set<SecureClientEventHandler>();
      listeners.add(typedHandler);
      this.customEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register client event handler.")
      );
    }

    return this;
  }

  public off(event: "connect", handler: SecureClientConnectHandler): this;
  public off(event: "disconnect", handler: SecureClientDisconnectHandler): this;
  public off(event: "ready", handler: SecureClientReadyHandler): this;
  public off(event: "error", handler: SecureErrorHandler): this;
  public off(event: string, handler: SecureClientEventHandler): this;
  public off(event: string, handler: unknown): this {
    try {
      if (event === "connect") {
        this.connectHandlers.delete(handler as SecureClientConnectHandler);
        return this;
      }

      if (event === "disconnect") {
        this.disconnectHandlers.delete(handler as SecureClientDisconnectHandler);
        return this;
      }

      if (event === READY_EVENT) {
        this.readyHandlers.delete(handler as SecureClientReadyHandler);
        return this;
      }

      if (event === "error") {
        this.errorHandlers.delete(handler as SecureErrorHandler);
        return this;
      }

      if (event === INTERNAL_HANDSHAKE_EVENT) {
        return this;
      }

      const listeners = this.customEventHandlers.get(event);

      if (!listeners) {
        return this;
      }

      listeners.delete(handler as SecureClientEventHandler);

      if (listeners.size === 0) {
        this.customEventHandlers.delete(event);
      }
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to remove client event handler.")
      );
    }

    return this;
  }

  public emit(event: string, data: unknown): boolean;
  public emit(event: string, data: unknown, callback: SecureAckCallback): boolean;
  public emit(event: string, data: unknown, options: SecureAckOptions): Promise<unknown>;
  public emit(
    event: string,
    data: unknown,
    options: SecureAckOptions,
    callback: SecureAckCallback
  ): boolean;
  public emit(
    event: string,
    data: unknown,
    callbackOrOptions?: SecureAckCallback | SecureAckOptions,
    maybeCallback?: SecureAckCallback
  ): boolean | Promise<unknown> {
    const ackArgs = resolveAckArguments(callbackOrOptions, maybeCallback);

    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Client socket is not connected.");
      }

      if (ackArgs.expectsAck) {
        const ackPromise = this.sendRpcRequest(event, data, ackArgs.timeoutMs);

        if (ackArgs.callback) {
          ackPromise
            .then((response) => {
              ackArgs.callback?.(null, response);
            })
            .catch((error) => {
              ackArgs.callback?.(
                normalizeToError(error, `ACK callback failed for event "${event}".`)
              );
            });

          return true;
        }

        return ackPromise;
      }

      const envelope: SecureEnvelope = { event, data };

      if (!this.isHandshakeReady()) {
        this.pendingPayloadQueue.push(envelope);
        return true;
      }

      void this.sendEncryptedEnvelope(envelope).catch(() => {
        return undefined;
      });
      return true;
    } catch (error) {
      const normalizedError = normalizeToError(error, "Failed to emit client event.");
      this.notifyError(normalizedError);

      if (ackArgs.callback) {
        ackArgs.callback(normalizedError);
        return false;
      }

      if (ackArgs.expectsAck) {
        return Promise.reject(normalizedError);
      }

      return false;
    }
  }

  private resolveReconnectConfig(
    reconnectOptions: boolean | SecureClientReconnectOptions | undefined
  ): Required<SecureClientReconnectOptions> {
    if (typeof reconnectOptions === "boolean") {
      return {
        enabled: reconnectOptions,
        initialDelayMs: DEFAULT_RECONNECT_INITIAL_DELAY_MS,
        maxDelayMs: DEFAULT_RECONNECT_MAX_DELAY_MS,
        factor: DEFAULT_RECONNECT_FACTOR,
        jitterRatio: DEFAULT_RECONNECT_JITTER_RATIO,
        maxAttempts: null
      };
    }

    const initialDelayMs = reconnectOptions?.initialDelayMs ?? DEFAULT_RECONNECT_INITIAL_DELAY_MS;
    const maxDelayMs = reconnectOptions?.maxDelayMs ?? DEFAULT_RECONNECT_MAX_DELAY_MS;
    const factor = reconnectOptions?.factor ?? DEFAULT_RECONNECT_FACTOR;
    const jitterRatio = reconnectOptions?.jitterRatio ?? DEFAULT_RECONNECT_JITTER_RATIO;
    const maxAttempts = reconnectOptions?.maxAttempts ?? null;

    if (!Number.isFinite(initialDelayMs) || initialDelayMs < 0) {
      throw new Error("Client reconnect initialDelayMs must be a non-negative number.");
    }

    if (!Number.isFinite(maxDelayMs) || maxDelayMs < 0) {
      throw new Error("Client reconnect maxDelayMs must be a non-negative number.");
    }

    if (maxDelayMs < initialDelayMs) {
      throw new Error("Client reconnect maxDelayMs must be greater than or equal to initialDelayMs.");
    }

    if (!Number.isFinite(factor) || factor < 1) {
      throw new Error("Client reconnect factor must be greater than or equal to 1.");
    }

    if (!Number.isFinite(jitterRatio) || jitterRatio < 0 || jitterRatio > 1) {
      throw new Error("Client reconnect jitterRatio must be between 0 and 1.");
    }

    if (
      maxAttempts !== null &&
      (!Number.isInteger(maxAttempts) || maxAttempts < 0)
    ) {
      throw new Error("Client reconnect maxAttempts must be a non-negative integer or null.");
    }

    return {
      enabled: reconnectOptions?.enabled ?? true,
      initialDelayMs,
      maxDelayMs,
      factor,
      jitterRatio,
      maxAttempts
    };
  }

  private scheduleReconnect(): void {
    if (!this.reconnectConfig.enabled || this.reconnectTimer) {
      return;
    }

    if (
      this.reconnectConfig.maxAttempts !== null &&
      this.reconnectAttemptCount >= this.reconnectConfig.maxAttempts
    ) {
      return;
    }

    this.reconnectAttemptCount += 1;
    const delayMs = this.computeReconnectDelay(this.reconnectAttemptCount);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delayMs);

    this.reconnectTimer.unref?.();
  }

  private computeReconnectDelay(attemptNumber: number): number {
    const exponentialDelay = Math.min(
      this.reconnectConfig.maxDelayMs,
      this.reconnectConfig.initialDelayMs *
        Math.pow(this.reconnectConfig.factor, Math.max(0, attemptNumber - 1))
    );

    if (this.reconnectConfig.jitterRatio === 0 || exponentialDelay === 0) {
      return Math.round(exponentialDelay);
    }

    const jitterDelta = exponentialDelay * this.reconnectConfig.jitterRatio;
    const jitterOffset = (Math.random() * 2 - 1) * jitterDelta;

    return Math.max(0, Math.round(exponentialDelay + jitterOffset));
  }

  private clearReconnectTimer(): void {
    if (!this.reconnectTimer) {
      return;
    }

    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }

  private createSocket(): WebSocket {
    if (this.options.protocols !== undefined) {
      return new WebSocket(this.url, this.options.protocols, this.options.wsOptions);
    }

    if (this.options.wsOptions !== undefined) {
      return new WebSocket(this.url, this.options.wsOptions);
    }

    return new WebSocket(this.url);
  }

  private bindSocketEvents(socket: WebSocket): void {
    socket.on("open", () => {
      this.clearReconnectTimer();
      this.reconnectAttemptCount = 0;
      this.sendInternalHandshake();
      this.notifyConnect();
    });

    socket.on("message", (rawData: RawData) => {
      this.handleIncomingMessage(rawData);
    });

    socket.on("close", (code: number, reason: Buffer) => {
      this.handleDisconnect(code, reason);
    });

    socket.on("error", (error: Error) => {
      this.notifyError(normalizeToError(error, "Client socket encountered an error."));
    });
  }

  private handleIncomingMessage(rawData: RawData): void {
    try {
      let envelope: SecureEnvelope | null = null;

      try {
        envelope = parseEnvelope(rawData);
      } catch {
        envelope = null;
      }

      if (envelope?.event === INTERNAL_HANDSHAKE_EVENT) {
        this.handleInternalHandshake(envelope.data);
        return;
      }

      if (envelope !== null) {
        this.notifyError(
          new Error(`Plaintext event "${envelope.event}" was rejected on client.`)
        );
        return;
      }

      if (!this.isHandshakeReady()) {
        this.notifyError(new Error("Encrypted payload was received before handshake completion."));
        return;
      }

      const encryptionKey = this.handshakeState?.encryptionKey;

      if (!encryptionKey) {
        this.notifyError(new Error("Missing encryption key for client payload decryption."));
        return;
      }

      let decryptedPayload: string;

      try {
        decryptedPayload = decryptSerializedEnvelope(rawData, encryptionKey);
      } catch {
        console.warn("Tampered data detected and dropped");
        return;
      }

      const decryptedEnvelope = parseEnvelopeFromText(decryptedPayload);

      if (decryptedEnvelope.event === INTERNAL_RPC_RESPONSE_EVENT) {
        this.handleRpcResponse(decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_RPC_REQUEST_EVENT) {
        void this.handleRpcRequest(decryptedEnvelope.data);
        return;
      }

      this.dispatchCustomEvent(decryptedEnvelope.event, decryptedEnvelope.data);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process incoming client message."));
    }
  }

  private handleDisconnect(code: number, reason: Buffer): void {
    try {
      this.socket = null;
      this.handshakeState = null;
      this.pendingPayloadQueue = [];
      this.rejectPendingRpcRequests(
        new Error("Client disconnected before ACK response was received.")
      );
      const decodedReason = decodeCloseReason(reason);

      for (const handler of this.disconnectHandlers) {
        try {
          handler(code, decodedReason);
        } catch (handlerError) {
          this.notifyError(
            normalizeToError(handlerError, "Client disconnect handler failed.")
          );
        }
      }

      if (!this.isManualDisconnectRequested) {
        this.scheduleReconnect();
      }

      this.isManualDisconnectRequested = false;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to handle client disconnect."));
    }
  }

  private dispatchCustomEvent(event: string, data: unknown): void {
    const handlers = this.customEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      return;
    }

    for (const handler of handlers) {
      try {
        const handlerResult = handler(data);

        if (isPromiseLike(handlerResult)) {
          void Promise.resolve(handlerResult).catch((error) => {
            this.notifyError(
              normalizeToError(
                error,
                `Client event handler failed for event ${event}.`
              )
            );
          });
        }
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Client event handler failed for event ${event}.`)
        );
      }
    }
  }

  private notifyConnect(): void {
    for (const handler of this.connectHandlers) {
      try {
        handler();
      } catch (error) {
        this.notifyError(normalizeToError(error, "Client connect handler failed."));
      }
    }
  }

  private notifyReady(): void {
    for (const handler of this.readyHandlers) {
      try {
        handler();
      } catch (error) {
        this.notifyError(normalizeToError(error, "Client ready handler failed."));
      }
    }
  }

  private notifyError(error: Error): void {
    if (this.errorHandlers.size === 0) {
      return;
    }

    for (const handler of this.errorHandlers) {
      try {
        handler(error);
      } catch {
        // Error handlers should not throw into the event loop.
      }
    }
  }

  private async sendEncryptedEnvelope(envelope: SecureEnvelope): Promise<void> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      const socketStateError = new Error("Client socket is not connected.");
      this.notifyError(socketStateError);
      throw socketStateError;
    }

    const encryptionKey = this.handshakeState?.encryptionKey;

    if (!encryptionKey) {
      const missingKeyError = new Error("Missing encryption key for client payload encryption.");
      this.notifyError(missingKeyError);
      throw missingKeyError;
    }

    try {
      const serializedEnvelope = await serializeEnvelope(envelope.event, envelope.data);
      const encryptedPayload = encryptSerializedEnvelope(serializedEnvelope, encryptionKey);
      this.socket.send(encryptedPayload);
    } catch (error) {
      const normalizedError = normalizeToError(error, "Failed to send encrypted client payload.");
      this.notifyError(normalizedError);
      throw normalizedError;
    }
  }

  private sendRpcRequest(
    event: string,
    data: unknown,
    timeoutMs: number
  ): Promise<unknown> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("Client socket is not connected for ACK request.");
    }

    const requestId = randomUUID();

    return new Promise<unknown>((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        this.pendingRpcRequests.delete(requestId);
        reject(new Error(`ACK response timed out after ${timeoutMs}ms for event "${event}".`));
      }, timeoutMs);

      timeoutHandle.unref?.();

      this.pendingRpcRequests.set(requestId, {
        resolve,
        reject,
        timeoutHandle
      });

      const rpcRequestEnvelope: SecureEnvelope<RpcRequestPayload> = {
        event: INTERNAL_RPC_REQUEST_EVENT,
        data: {
          id: requestId,
          event,
          data
        }
      };

      if (!this.isHandshakeReady()) {
        this.pendingPayloadQueue.push(rpcRequestEnvelope);
        return;
      }

      void this.sendEncryptedEnvelope(rpcRequestEnvelope).catch((error) => {
        clearTimeout(timeoutHandle);
        this.pendingRpcRequests.delete(requestId);
        reject(
          normalizeToError(error, `Failed to dispatch ACK request for event "${event}".`)
        );
      });
    });
  }

  private handleRpcResponse(data: unknown): void {
    try {
      const responsePayload = parseRpcResponsePayload(data);
      const pendingRequest = this.pendingRpcRequests.get(responsePayload.id);

      if (!pendingRequest) {
        return;
      }

      clearTimeout(pendingRequest.timeoutHandle);
      this.pendingRpcRequests.delete(responsePayload.id);

      if (responsePayload.ok) {
        pendingRequest.resolve(responsePayload.data);
        return;
      }

      pendingRequest.reject(
        new Error(responsePayload.error ?? "ACK request failed without an error message.")
      );
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process client ACK response."));
    }
  }

  private async handleRpcRequest(data: unknown): Promise<void> {
    let rpcRequestPayload: RpcRequestPayload;

    try {
      rpcRequestPayload = parseRpcRequestPayload(data);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Invalid client ACK request payload."));
      return;
    }

    try {
      const ackResponse = await this.executeRpcRequestHandler(
        rpcRequestPayload.event,
        rpcRequestPayload.data
      );

      await this.sendEncryptedEnvelope({
        event: INTERNAL_RPC_RESPONSE_EVENT,
        data: {
          id: rpcRequestPayload.id,
          ok: true,
          data: ackResponse
        } satisfies RpcResponsePayload
      });
    } catch (error) {
      const normalizedError = normalizeToError(error, "Client ACK request handler failed.");

      await this.sendEncryptedEnvelope({
        event: INTERNAL_RPC_RESPONSE_EVENT,
        data: {
          id: rpcRequestPayload.id,
          ok: false,
          error: normalizedError.message
        } satisfies RpcResponsePayload
      });

      this.notifyError(normalizedError);
    }
  }

  private async executeRpcRequestHandler(event: string, data: unknown): Promise<unknown> {
    const handlers = this.customEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      throw new Error(`No handler is registered for ACK request event "${event}".`);
    }

    const firstHandler = handlers.values().next().value as SecureClientEventHandler;
    return Promise.resolve(firstHandler(data));
  }

  private rejectPendingRpcRequests(error: Error): void {
    for (const pendingRequest of this.pendingRpcRequests.values()) {
      clearTimeout(pendingRequest.timeoutHandle);
      pendingRequest.reject(error);
    }

    this.pendingRpcRequests.clear();
  }

  private createClientHandshakeState(): ClientHandshakeState {
    const { ecdh, localPublicKey } = createEphemeralHandshakeState();

    return {
      ecdh,
      localPublicKey,
      isReady: false,
      sharedSecret: null,
      encryptionKey: null
    };
  }

  private sendInternalHandshake(): void {
    try {
      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        return;
      }

      if (!this.handshakeState) {
        throw new Error("Missing client handshake state.");
      }

      this.socket.send(
        serializePlainEnvelope(INTERNAL_HANDSHAKE_EVENT, {
          publicKey: this.handshakeState.localPublicKey
        })
      );
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send client handshake payload."));
    }
  }

  private handleInternalHandshake(data: unknown): void {
    try {
      const payload = parseHandshakePayload(data);

      if (!this.handshakeState) {
        throw new Error("Missing client handshake state.");
      }

      if (this.handshakeState.isReady) {
        return;
      }

      const remotePublicKey = Buffer.from(payload.publicKey, "base64");
      const sharedSecret = this.handshakeState.ecdh.computeSecret(remotePublicKey);

      this.handshakeState.sharedSecret = sharedSecret;
      this.handshakeState.encryptionKey = deriveEncryptionKey(sharedSecret);
      this.handshakeState.isReady = true;

      void this.flushPendingPayloadQueue();
      this.notifyReady();
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to complete client handshake."));
    }
  }

  private isHandshakeReady(): boolean {
    return this.handshakeState?.isReady ?? false;
  }

  private async flushPendingPayloadQueue(): Promise<void> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN || !this.isHandshakeReady()) {
      return;
    }

    const pendingPayloads = this.pendingPayloadQueue;
    this.pendingPayloadQueue = [];

    for (const envelope of pendingPayloads) {
      await this.sendEncryptedEnvelope(envelope);
    }
  }
}
