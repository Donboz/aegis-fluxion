import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHmac,
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from "node:crypto";
import type { ECDH } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { PassThrough, Readable } from "node:stream";
import WebSocket, { WebSocketServer } from "ws";
import type {
  ClientOptions,
  RawData,
  ServerOptions as WebSocketServerOptions
} from "ws";

const DEFAULT_CLOSE_CODE = 1000;
const DEFAULT_CLOSE_REASON = "";
const POLICY_VIOLATION_CLOSE_CODE = 1008;
const POLICY_VIOLATION_CLOSE_REASON = "Connection rejected by middleware.";
const INTERNAL_HANDSHAKE_EVENT = "__handshake";
const INTERNAL_SESSION_TICKET_EVENT = "__session:ticket";
const INTERNAL_RPC_REQUEST_EVENT = "__rpc:req";
const INTERNAL_RPC_RESPONSE_EVENT = "__rpc:res";
const INTERNAL_STREAM_FRAME_EVENT = "__stream:frame";
const READY_EVENT = "ready";
const HANDSHAKE_CURVE = "prime256v1";
const HANDSHAKE_PROTOCOL_VERSION = 1;
const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const GCM_IV_LENGTH = 12;
const GCM_AUTH_TAG_LENGTH = 16;
const ENCRYPTION_KEY_LENGTH = 32;
const ENCRYPTED_PACKET_VERSION = 1;
const ENCRYPTED_PACKET_PREFIX_LENGTH = 1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;
const SESSION_TICKET_VERSION = 1;
const BINARY_PAYLOAD_MARKER = "__afxBinaryPayload";
const BINARY_PAYLOAD_VERSION = 1;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 15_000;
const DEFAULT_HEARTBEAT_TIMEOUT_MS = 15_000;
const DEFAULT_SESSION_RESUMPTION_ENABLED = true;
const DEFAULT_SESSION_TICKET_TTL_MS = 10 * 60_000;
const DEFAULT_SESSION_TICKET_MAX_CACHE_SIZE = 10_000;
const STREAM_FRAME_VERSION = 1;
const DEFAULT_STREAM_CHUNK_SIZE_BYTES = 64 * 1024;
const MAX_STREAM_CHUNK_SIZE_BYTES = 1024 * 1024;
const RESUMPTION_NONCE_LENGTH = 16;
const DEFAULT_RECONNECT_INITIAL_DELAY_MS = 250;
const DEFAULT_RECONNECT_MAX_DELAY_MS = 10_000;
const DEFAULT_RECONNECT_FACTOR = 2;
const DEFAULT_RECONNECT_JITTER_RATIO = 0.2;
const DEFAULT_RPC_TIMEOUT_MS = 5_000;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 1_000;
const DEFAULT_RATE_LIMIT_MAX_EVENTS_PER_CONNECTION = 120;
const DEFAULT_RATE_LIMIT_MAX_EVENTS_PER_IP = 300;
const DEFAULT_RATE_LIMIT_THROTTLE_MS = 150;
const DEFAULT_RATE_LIMIT_MAX_THROTTLE_MS = 2_000;
const DEFAULT_RATE_LIMIT_DISCONNECT_AFTER_VIOLATIONS = 4;
const DEFAULT_RATE_LIMIT_CLOSE_CODE = 1013;
const DEFAULT_RATE_LIMIT_CLOSE_REASON =
  "Rate limit exceeded. Please retry later.";
const SECURE_SERVER_ADAPTER_MESSAGE_VERSION = 1;

interface HandshakeHelloPayload {
  type: "hello";
  protocolVersion: typeof HANDSHAKE_PROTOCOL_VERSION;
  publicKey: string;
}

interface HandshakeResumePayload {
  type: "resume";
  protocolVersion: typeof HANDSHAKE_PROTOCOL_VERSION;
  sessionId: string;
  clientNonce: string;
  clientProof: string;
}

interface HandshakeResumeAckPayload {
  type: "resume-ack";
  protocolVersion: typeof HANDSHAKE_PROTOCOL_VERSION;
  ok: boolean;
  sessionId?: string;
  serverProof?: string;
  reason?: string;
}

type HandshakePayload =
  | HandshakeHelloPayload
  | HandshakeResumePayload
  | HandshakeResumeAckPayload;

interface SessionTicketPayload {
  version: typeof SESSION_TICKET_VERSION;
  sessionId: string;
  secret: string;
  issuedAt: number;
  expiresAt: number;
}

interface ServerSessionTicketRecord {
  sessionId: string;
  secret: Buffer;
  issuedAt: number;
  expiresAt: number;
}

interface ClientSessionTicketRecord {
  sessionId: string;
  secret: Buffer;
  issuedAt: number;
  expiresAt: number;
}

interface ClientResumeAttemptState {
  status: "pending" | "accepted" | "failed";
  sessionId: string;
  clientNonce: Buffer;
  resumedKey: Buffer;
}

interface ServerHandshakeState {
  ecdh: ECDH;
  localPublicKey: string;
  isReady: boolean;
}

interface ClientHandshakeState {
  ecdh: ECDH;
  localPublicKey: string;
  clientHelloSent: boolean;
  pendingServerPublicKey: string | null;
  resumeAttempt: ClientResumeAttemptState | null;
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

type SecureChunkSourceValue = Buffer | Uint8Array | ArrayBuffer | string;

interface StreamFrameStartPayload {
  version: typeof STREAM_FRAME_VERSION;
  type: "start";
  streamId: string;
  event: string;
  metadata?: Record<string, unknown>;
  totalBytes?: number;
}

interface StreamFrameChunkPayload {
  version: typeof STREAM_FRAME_VERSION;
  type: "chunk";
  streamId: string;
  index: number;
  payload: string;
  byteLength: number;
}

interface StreamFrameEndPayload {
  version: typeof STREAM_FRAME_VERSION;
  type: "end";
  streamId: string;
  chunkCount: number;
  totalBytes: number;
}

interface StreamFrameAbortPayload {
  version: typeof STREAM_FRAME_VERSION;
  type: "abort";
  streamId: string;
  reason: string;
}

type StreamFramePayload =
  | StreamFrameStartPayload
  | StreamFrameChunkPayload
  | StreamFrameEndPayload
  | StreamFrameAbortPayload;

interface IncomingServerStreamState {
  info: SecureIncomingStreamInfo;
  stream: PassThrough;
  expectedChunkIndex: number;
  receivedBytes: number;
}

interface IncomingClientStreamState {
  info: SecureIncomingStreamInfo;
  stream: PassThrough;
  expectedChunkIndex: number;
  receivedBytes: number;
}

interface SecureServerRateLimitBucket {
  windowStartedAt: number;
  count: number;
  violationCount: number;
  throttleUntil: number;
  lastSeenAt: number;
}

interface SecureServerRateLimitDecision {
  shouldDisconnect: boolean;
  shouldDrop: boolean;
  throttleDelayMs: number;
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

export type SecureChunkedStreamSource =
  | Buffer
  | Uint8Array
  | Readable
  | AsyncIterable<SecureChunkSourceValue>;

export interface SecureChunkedStreamOptions {
  chunkSizeBytes?: number;
  metadata?: Record<string, unknown>;
  totalBytes?: number;
  signal?: AbortSignal;
}

export interface SecureStreamSendResult {
  streamId: string;
  chunkCount: number;
  totalBytes: number;
}

export interface SecureIncomingStreamInfo {
  streamId: string;
  event: string;
  metadata?: Record<string, unknown>;
  totalBytes?: number;
  startedAt: number;
}

export type SecureServerStreamHandler = (
  stream: Readable,
  info: SecureIncomingStreamInfo,
  client: SecureServerClient
) => void | Promise<void>;

export type SecureClientStreamHandler = (
  stream: Readable,
  info: SecureIncomingStreamInfo
) => void | Promise<void>;

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

export type SecureServerRateLimitAction = "throttle" | "disconnect";

export interface SecureServerRateLimitOptions {
  enabled?: boolean;
  windowMs?: number;
  maxEventsPerConnection?: number;
  maxEventsPerIp?: number;
  action?: SecureServerRateLimitAction;
  throttleMs?: number;
  maxThrottleMs?: number;
  disconnectAfterViolations?: number;
  disconnectCode?: number;
  disconnectReason?: string;
}

export interface SecureServerSessionResumptionOptions {
  enabled?: boolean;
  ticketTtlMs?: number;
  maxCachedTickets?: number;
}

export type SecureServerAdapterMessageScope = "broadcast" | "room";

export interface SecureServerAdapterMessage {
  version: typeof SECURE_SERVER_ADAPTER_MESSAGE_VERSION;
  originServerId: string;
  scope: SecureServerAdapterMessageScope;
  event: string;
  data: unknown;
  emittedAt: number;
  room?: string;
}

export interface SecureServerAdapter {
  attach: (server: SecureServer) => void | Promise<void>;
  publish: (message: SecureServerAdapterMessage) => void | Promise<void>;
  detach?: (server: SecureServer) => void | Promise<void>;
}

export interface SecureServerOptions extends WebSocketServerOptions {
  heartbeat?: SecureServerHeartbeatOptions;
  rateLimit?: SecureServerRateLimitOptions;
  sessionResumption?: SecureServerSessionResumptionOptions;
  adapter?: SecureServerAdapter;
}

export interface SecureClientReconnectOptions {
  enabled?: boolean;
  initialDelayMs?: number;
  maxDelayMs?: number;
  factor?: number;
  jitterRatio?: number;
  maxAttempts?: number | null;
}

export interface SecureClientSessionResumptionOptions {
  enabled?: boolean;
  maxAcceptedTicketTtlMs?: number;
}

export interface SecureClientOptions {
  protocols?: string | string[];
  wsOptions?: ClientOptions;
  autoConnect?: boolean;
  reconnect?: boolean | SecureClientReconnectOptions;
  sessionResumption?: boolean | SecureClientSessionResumptionOptions;
}

export interface SecureServerClient {
  id: string;
  socket: WebSocket;
  request: IncomingMessage;
  metadata: ReadonlyMap<string, unknown>;
  emit: (
    event: string,
    data: unknown,
    callbackOrOptions?: SecureAckCallback | SecureAckOptions,
    maybeCallback?: SecureAckCallback
  ) => boolean | Promise<unknown>;
  emitStream: (
    event: string,
    source: SecureChunkedStreamSource,
    options?: SecureChunkedStreamOptions
  ) => Promise<SecureStreamSendResult>;
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

export interface SecureServerConnectionMiddlewareContext {
  phase: "connection";
  socket: WebSocket;
  request: IncomingMessage;
  metadata: Map<string, unknown>;
}

export interface SecureServerMessageMiddlewareContext {
  phase: "incoming" | "outgoing";
  client: SecureServerClient;
  event: string;
  data: unknown;
  metadata: Map<string, unknown>;
}

export type SecureServerMiddlewareContext =
  | SecureServerConnectionMiddlewareContext
  | SecureServerMessageMiddlewareContext;

export type SecureServerMiddlewareNext = () => Promise<void>;

export type SecureServerMiddleware = (
  context: SecureServerMiddlewareContext,
  next: SecureServerMiddlewareNext
) => void | Promise<void>;

export function normalizeSecureServerAdapterMessage(
  value: unknown
): SecureServerAdapterMessage {
  if (!isPlainObject(value)) {
    throw new Error("SecureServer adapter message must be a plain object.");
  }

  if (value.version !== SECURE_SERVER_ADAPTER_MESSAGE_VERSION) {
    throw new Error(
      `Unsupported SecureServer adapter message version: ${String(value.version)}.`
    );
  }

  if (
    typeof value.originServerId !== "string" ||
    value.originServerId.trim().length === 0
  ) {
    throw new Error("SecureServer adapter message originServerId must be a non-empty string.");
  }

  if (value.scope !== "broadcast" && value.scope !== "room") {
    throw new Error('SecureServer adapter message scope must be either "broadcast" or "room".');
  }

  if (typeof value.event !== "string" || value.event.trim().length === 0) {
    throw new Error("SecureServer adapter message event must be a non-empty string.");
  }

  if (typeof value.emittedAt !== "number" || !Number.isFinite(value.emittedAt)) {
    throw new Error("SecureServer adapter message emittedAt must be a finite number.");
  }

  if (value.scope === "room") {
    if (typeof value.room !== "string" || value.room.trim().length === 0) {
      throw new Error("SecureServer adapter message room must be a non-empty string.");
    }

    return {
      version: SECURE_SERVER_ADAPTER_MESSAGE_VERSION,
      originServerId: value.originServerId,
      scope: value.scope,
      event: value.event,
      data: value.data,
      emittedAt: value.emittedAt,
      room: value.room.trim()
    };
  }

  return {
    version: SECURE_SERVER_ADAPTER_MESSAGE_VERSION,
    originServerId: value.originServerId,
    scope: value.scope,
    event: value.event,
    data: value.data,
    emittedAt: value.emittedAt
  };
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

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
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
    event === INTERNAL_SESSION_TICKET_EVENT ||
    event === INTERNAL_RPC_REQUEST_EVENT ||
    event === INTERNAL_RPC_RESPONSE_EVENT ||
    event === INTERNAL_STREAM_FRAME_EVENT ||
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

function normalizeStreamChunkSize(chunkSizeBytes: number | undefined): number {
  const resolvedChunkSize = chunkSizeBytes ?? DEFAULT_STREAM_CHUNK_SIZE_BYTES;

  if (!Number.isInteger(resolvedChunkSize) || resolvedChunkSize <= 0) {
    throw new Error("Stream chunkSizeBytes must be a positive integer.");
  }

  if (resolvedChunkSize > MAX_STREAM_CHUNK_SIZE_BYTES) {
    throw new Error(
      `Stream chunkSizeBytes cannot exceed ${MAX_STREAM_CHUNK_SIZE_BYTES} bytes.`
    );
  }

  return resolvedChunkSize;
}

function resolveKnownStreamSourceSize(
  source: SecureChunkedStreamSource,
  hint: number | undefined
): number | undefined {
  if (hint !== undefined) {
    if (!Number.isInteger(hint) || hint < 0) {
      throw new Error("Stream totalBytes must be a non-negative integer.");
    }

    return hint;
  }

  if (Buffer.isBuffer(source)) {
    return source.length;
  }

  if (source instanceof Uint8Array) {
    return source.byteLength;
  }

  return undefined;
}

function normalizeChunkSourceValue(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }

  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }

  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }

  throw new Error("Stream source yielded an unsupported chunk value.");
}

function isAsyncIterableValue(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    Symbol.asyncIterator in value
  );
}

function isReadableSource(value: unknown): value is Readable {
  return value instanceof Readable;
}

function splitChunkBuffer(chunk: Buffer, chunkSizeBytes: number): Buffer[] {
  if (chunk.length <= chunkSizeBytes) {
    return [chunk];
  }

  const splitChunks: Buffer[] = [];

  for (let offset = 0; offset < chunk.length; offset += chunkSizeBytes) {
    splitChunks.push(chunk.subarray(offset, offset + chunkSizeBytes));
  }

  return splitChunks;
}

async function* createChunkStreamIterator(
  source: SecureChunkedStreamSource,
  chunkSizeBytes: number
): AsyncGenerator<Buffer> {
  if (Buffer.isBuffer(source)) {
    yield* splitChunkBuffer(source, chunkSizeBytes);
    return;
  }

  if (source instanceof Uint8Array) {
    yield* splitChunkBuffer(
      Buffer.from(source.buffer, source.byteOffset, source.byteLength),
      chunkSizeBytes
    );
    return;
  }

  if (isReadableSource(source) || isAsyncIterableValue(source)) {
    for await (const chunkValue of source) {
      const normalizedChunk = normalizeChunkSourceValue(chunkValue);

      if (normalizedChunk.length === 0) {
        continue;
      }

      yield* splitChunkBuffer(normalizedChunk, chunkSizeBytes);
    }

    return;
  }

  throw new Error("Unsupported stream source type.");
}

function parseStreamFramePayload(data: unknown): StreamFramePayload {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid stream frame payload format.");
  }

  const payload = data as Partial<StreamFramePayload> & {
    metadata?: unknown;
  };

  if (payload.version !== STREAM_FRAME_VERSION) {
    throw new Error(`Unsupported stream frame version: ${String(payload.version)}.`);
  }

  if (typeof payload.streamId !== "string" || payload.streamId.trim().length === 0) {
    throw new Error("Stream frame streamId must be a non-empty string.");
  }

  if (payload.type === "start") {
    if (typeof payload.event !== "string" || payload.event.trim().length === 0) {
      throw new Error("Stream start frame event must be a non-empty string.");
    }

    if (
      payload.totalBytes !== undefined &&
      (!Number.isInteger(payload.totalBytes) || payload.totalBytes < 0)
    ) {
      throw new Error("Stream start frame totalBytes must be a non-negative integer.");
    }

    if (payload.metadata !== undefined && !isPlainObject(payload.metadata)) {
      throw new Error("Stream start frame metadata must be a plain object when provided.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "start",
      streamId: payload.streamId.trim(),
      event: payload.event.trim(),
      ...(payload.metadata ? { metadata: payload.metadata } : {}),
      ...(payload.totalBytes !== undefined
        ? { totalBytes: payload.totalBytes }
        : {})
    };
  }

  if (payload.type === "chunk") {
    const { index, byteLength } = payload;

    if (typeof index !== "number" || !Number.isInteger(index) || index < 0) {
      throw new Error("Stream chunk frame index must be a non-negative integer.");
    }

    if (typeof payload.payload !== "string" || payload.payload.length === 0) {
      throw new Error("Stream chunk frame payload must be a non-empty base64 string.");
    }

    if (
      typeof byteLength !== "number" ||
      !Number.isInteger(byteLength) ||
      byteLength <= 0
    ) {
      throw new Error("Stream chunk frame byteLength must be a positive integer.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "chunk",
      streamId: payload.streamId.trim(),
      index,
      payload: payload.payload,
      byteLength
    };
  }

  if (payload.type === "end") {
    const { chunkCount, totalBytes } = payload;

    if (
      typeof chunkCount !== "number" ||
      !Number.isInteger(chunkCount) ||
      chunkCount < 0
    ) {
      throw new Error("Stream end frame chunkCount must be a non-negative integer.");
    }

    if (
      typeof totalBytes !== "number" ||
      !Number.isInteger(totalBytes) ||
      totalBytes < 0
    ) {
      throw new Error("Stream end frame totalBytes must be a non-negative integer.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "end",
      streamId: payload.streamId.trim(),
      chunkCount,
      totalBytes
    };
  }

  if (payload.type === "abort") {
    if (typeof payload.reason !== "string" || payload.reason.trim().length === 0) {
      throw new Error("Stream abort frame reason must be a non-empty string.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "abort",
      streamId: payload.streamId.trim(),
      reason: payload.reason.trim()
    };
  }

  throw new Error("Unsupported stream frame type.");
}

async function transmitChunkedStreamFrames(
  event: string,
  source: SecureChunkedStreamSource,
  options: SecureChunkedStreamOptions | undefined,
  sendFrame: (framePayload: StreamFramePayload) => Promise<void>
): Promise<SecureStreamSendResult> {
  const chunkSizeBytes = normalizeStreamChunkSize(options?.chunkSizeBytes);
  const totalBytesHint = resolveKnownStreamSourceSize(source, options?.totalBytes);

  if (options?.metadata !== undefined && !isPlainObject(options.metadata)) {
    throw new Error("Stream metadata must be a plain object when provided.");
  }

  if (options?.signal?.aborted) {
    throw new Error("Stream transfer aborted before dispatch.");
  }

  const streamId = randomUUID();
  let chunkCount = 0;
  let totalBytes = 0;

  await sendFrame({
    version: STREAM_FRAME_VERSION,
    type: "start",
    streamId,
    event,
    ...(options?.metadata ? { metadata: options.metadata } : {}),
    ...(totalBytesHint !== undefined ? { totalBytes: totalBytesHint } : {})
  });

  try {
    for await (const chunkBuffer of createChunkStreamIterator(source, chunkSizeBytes)) {
      if (options?.signal?.aborted) {
        throw new Error("Stream transfer aborted by caller signal.");
      }

      if (chunkBuffer.length === 0) {
        continue;
      }

      await sendFrame({
        version: STREAM_FRAME_VERSION,
        type: "chunk",
        streamId,
        index: chunkCount,
        payload: chunkBuffer.toString("base64"),
        byteLength: chunkBuffer.length
      });

      chunkCount += 1;
      totalBytes += chunkBuffer.length;
    }

    if (totalBytesHint !== undefined && totalBytes !== totalBytesHint) {
      throw new Error(
        `Stream totalBytes mismatch. Expected ${totalBytesHint}, received ${totalBytes}.`
      );
    }

    await sendFrame({
      version: STREAM_FRAME_VERSION,
      type: "end",
      streamId,
      chunkCount,
      totalBytes
    });

    return {
      streamId,
      chunkCount,
      totalBytes
    };
  } catch (error) {
    const normalizedError = normalizeToError(
      error,
      `Chunked stream transfer failed for event "${event}".`
    );

    try {
      await sendFrame({
        version: STREAM_FRAME_VERSION,
        type: "abort",
        streamId,
        reason: normalizedError.message
      });
    } catch {
      // Best effort abort frame dispatch.
    }

    throw normalizedError;
  }
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

function decodeBase64ToBuffer(value: string, fieldName: string): Buffer {
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a base64 string.`);
  }

  const normalizedValue = value.trim();

  if (normalizedValue.length === 0) {
    throw new Error(`${fieldName} must be a non-empty base64 string.`);
  }

  const decodedBuffer = Buffer.from(normalizedValue, "base64");

  if (decodedBuffer.length === 0) {
    throw new Error(`${fieldName} could not be decoded from base64.`);
  }

  const canonicalInput = normalizedValue.replace(/=+$/u, "");
  const canonicalDecoded = decodedBuffer.toString("base64").replace(/=+$/u, "");

  if (canonicalInput !== canonicalDecoded) {
    throw new Error(`${fieldName} is not valid base64 content.`);
  }

  return decodedBuffer;
}

function equalsConstantTime(left: Buffer, right: Buffer): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(left, right);
}

function createResumeClientProof(
  sessionSecret: Buffer,
  sessionId: string,
  clientNonce: Buffer
): Buffer {
  return createHmac("sha256", sessionSecret)
    .update("afx-resume-client-proof:v1")
    .update(sessionId)
    .update(clientNonce)
    .digest();
}

function createResumeServerProof(
  resumedKey: Buffer,
  sessionId: string,
  clientNonce: Buffer
): Buffer {
  return createHmac("sha256", resumedKey)
    .update("afx-resume-server-proof:v1")
    .update(sessionId)
    .update(clientNonce)
    .digest();
}

function deriveSessionTicketSecret(baseKey: Buffer): Buffer {
  return createHmac("sha256", baseKey)
    .update("afx-session-ticket:v1")
    .digest();
}

function deriveResumedEncryptionKey(sessionSecret: Buffer, clientNonce: Buffer): Buffer {
  const derivedKey = createHash("sha256")
    .update("afx-resume-encryption-key:v1")
    .update(sessionSecret)
    .update(clientNonce)
    .digest();

  if (derivedKey.length !== ENCRYPTION_KEY_LENGTH) {
    throw new Error("Failed to derive a valid resumed AES-256 key.");
  }

  return derivedKey;
}

function parseHandshakePayload(data: unknown): HandshakePayload {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid handshake payload format.");
  }

  const payload = data as Record<string, unknown>;

  if (typeof payload.type !== "string") {
    if (typeof payload.publicKey === "string" && payload.publicKey.length > 0) {
      return {
        type: "hello",
        protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
        publicKey: payload.publicKey
      };
    }

    throw new Error("Handshake payload must include a valid type.");
  }

  const protocolVersion =
    payload.protocolVersion === undefined
      ? HANDSHAKE_PROTOCOL_VERSION
      : payload.protocolVersion;

  if (protocolVersion !== HANDSHAKE_PROTOCOL_VERSION) {
    throw new Error(
      `Unsupported handshake protocol version: ${String(protocolVersion)}.`
    );
  }

  if (payload.type === "hello") {
    if (typeof payload.publicKey !== "string" || payload.publicKey.length === 0) {
      throw new Error("Handshake hello payload must include a non-empty public key.");
    }

    return {
      type: "hello",
      protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
      publicKey: payload.publicKey
    };
  }

  if (payload.type === "resume") {
    if (typeof payload.sessionId !== "string" || payload.sessionId.trim().length === 0) {
      throw new Error("Handshake resume payload must include a non-empty sessionId.");
    }

    if (typeof payload.clientNonce !== "string" || payload.clientNonce.length === 0) {
      throw new Error("Handshake resume payload must include a non-empty clientNonce.");
    }

    if (typeof payload.clientProof !== "string" || payload.clientProof.length === 0) {
      throw new Error("Handshake resume payload must include a non-empty clientProof.");
    }

    return {
      type: "resume",
      protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
      sessionId: payload.sessionId.trim(),
      clientNonce: payload.clientNonce,
      clientProof: payload.clientProof
    };
  }

  if (payload.type === "resume-ack") {
    if (typeof payload.ok !== "boolean") {
      throw new Error("Handshake resume-ack payload must include boolean ok.");
    }

    const normalizedPayload: HandshakeResumeAckPayload = {
      type: "resume-ack",
      protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
      ok: payload.ok
    };

    if (typeof payload.sessionId === "string" && payload.sessionId.trim().length > 0) {
      normalizedPayload.sessionId = payload.sessionId.trim();
    }

    if (typeof payload.serverProof === "string" && payload.serverProof.length > 0) {
      normalizedPayload.serverProof = payload.serverProof;
    }

    if (typeof payload.reason === "string" && payload.reason.trim().length > 0) {
      normalizedPayload.reason = payload.reason.trim();
    }

    return normalizedPayload;
  }

  throw new Error(`Unsupported handshake payload type: ${payload.type}.`);
}

function parseSessionTicketPayload(data: unknown): SessionTicketPayload {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid session ticket payload format.");
  }

  const payload = data as Partial<SessionTicketPayload>;

  if (payload.version !== SESSION_TICKET_VERSION) {
    throw new Error(
      `Unsupported session ticket payload version: ${String(payload.version)}.`
    );
  }

  if (typeof payload.sessionId !== "string" || payload.sessionId.trim().length === 0) {
    throw new Error("Session ticket payload must include a non-empty sessionId.");
  }

  if (typeof payload.secret !== "string" || payload.secret.length === 0) {
    throw new Error("Session ticket payload must include a non-empty secret.");
  }

  if (typeof payload.issuedAt !== "number" || !Number.isFinite(payload.issuedAt)) {
    throw new Error("Session ticket payload issuedAt must be a finite number.");
  }

  if (typeof payload.expiresAt !== "number" || !Number.isFinite(payload.expiresAt)) {
    throw new Error("Session ticket payload expiresAt must be a finite number.");
  }

  if (payload.expiresAt <= payload.issuedAt) {
    throw new Error("Session ticket payload expiresAt must be greater than issuedAt.");
  }

  return {
    version: SESSION_TICKET_VERSION,
    sessionId: payload.sessionId.trim(),
    secret: payload.secret,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt
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
  private readonly instanceId = randomUUID();

  private readonly socketServer: WebSocketServer;

  private adapter: SecureServerAdapter | null = null;

  private readonly heartbeatConfig: Required<SecureServerHeartbeatOptions>;

  private readonly rateLimitConfig: Required<SecureServerRateLimitOptions>;

  private readonly sessionResumptionConfig: Required<SecureServerSessionResumptionOptions>;

  private heartbeatIntervalHandle: ReturnType<typeof setInterval> | null = null;

  private readonly clientsById = new Map<string, SecureServerClient>();

  private readonly clientIdBySocket = new Map<WebSocket, string>();

  private readonly customEventHandlers = new Map<string, Set<SecureServerEventHandler>>();

  private readonly streamEventHandlers = new Map<string, Set<SecureServerStreamHandler>>();

  private readonly connectionHandlers = new Set<SecureServerConnectionHandler>();

  private readonly disconnectHandlers = new Set<SecureServerDisconnectHandler>();

  private readonly readyHandlers = new Set<SecureServerReadyHandler>();

  private readonly errorHandlers = new Set<SecureErrorHandler>();

  private readonly middlewareHandlers: SecureServerMiddleware[] = [];

  private readonly handshakeStateBySocket = new WeakMap<WebSocket, ServerHandshakeState>();

  private readonly middlewareMetadataBySocket = new WeakMap<
    WebSocket,
    Map<string, unknown>
  >();

  private readonly sharedSecretBySocket = new WeakMap<WebSocket, Buffer>();

  private readonly encryptionKeyBySocket = new WeakMap<WebSocket, Buffer>();

  private readonly pendingPayloadsBySocket = new WeakMap<WebSocket, SecureEnvelope[]>();

  private readonly incomingStreamsBySocket = new WeakMap<
    WebSocket,
    Map<string, IncomingServerStreamState>
  >();

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

  private readonly clientIpByClientId = new Map<string, string>();

  private readonly rateLimitBucketsByClientId = new Map<
    string,
    SecureServerRateLimitBucket
  >();

  private readonly rateLimitBucketsByIp = new Map<
    string,
    SecureServerRateLimitBucket
  >();

  private readonly sessionTicketStore = new Map<string, ServerSessionTicketRecord>();

  public constructor(options: SecureServerOptions) {
    const { heartbeat, rateLimit, sessionResumption, adapter, ...socketServerOptions } = options;

    this.heartbeatConfig = this.resolveHeartbeatConfig(heartbeat);
    this.rateLimitConfig = this.resolveRateLimitConfig(rateLimit);
    this.sessionResumptionConfig = this.resolveSessionResumptionConfig(sessionResumption);
    this.socketServer = new WebSocketServer(socketServerOptions);
    this.bindSocketServerEvents();
    this.startHeartbeatLoop();

    if (adapter) {
      void this.setAdapter(adapter).catch(() => {
        return undefined;
      });
    }
  }

  public get clientCount(): number {
    return this.clientsById.size;
  }

  public get serverId(): string {
    return this.instanceId;
  }

  public get clients(): ReadonlyMap<string, SecureServerClient> {
    return this.clientsById;
  }

  public async setAdapter(adapter: SecureServerAdapter | null): Promise<void> {
    const previousAdapter = this.adapter;

    if (previousAdapter === adapter) {
      return;
    }

    try {
      if (previousAdapter?.detach) {
        await Promise.resolve(previousAdapter.detach(this));
      }

      this.adapter = null;

      if (!adapter) {
        return;
      }

      await Promise.resolve(adapter.attach(this));
      this.adapter = adapter;
    } catch (error) {
      const normalizedError = normalizeToError(
        error,
        "Failed to set SecureServer adapter."
      );

      this.notifyError(normalizedError);
      throw normalizedError;
    }
  }

  public async handleAdapterMessage(message: unknown): Promise<void> {
    try {
      const normalizedMessage = normalizeSecureServerAdapterMessage(message);

      if (normalizedMessage.originServerId === this.instanceId) {
        return;
      }

      if (normalizedMessage.scope === "broadcast") {
        this.emitLocally(normalizedMessage.event, normalizedMessage.data);
        return;
      }

      if (!normalizedMessage.room) {
        return;
      }

      this.emitToRoom(
        normalizedMessage.room,
        normalizedMessage.event,
        normalizedMessage.data,
        false
      );
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to process SecureServer adapter message.")
      );
    }
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

      if (event === INTERNAL_HANDSHAKE_EVENT || event === INTERNAL_SESSION_TICKET_EVENT) {
        throw new Error(`The event "${event}" is reserved for internal use.`);
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

      if (event === INTERNAL_HANDSHAKE_EVENT || event === INTERNAL_SESSION_TICKET_EVENT) {
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

  public onStream(event: string, handler: SecureServerStreamHandler): this {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be used as a stream event.`);
      }

      const listeners = this.streamEventHandlers.get(event) ?? new Set<SecureServerStreamHandler>();
      listeners.add(handler);
      this.streamEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register server stream handler.")
      );
    }

    return this;
  }

  public offStream(event: string, handler: SecureServerStreamHandler): this {
    try {
      const listeners = this.streamEventHandlers.get(event);

      if (!listeners) {
        return this;
      }

      listeners.delete(handler);

      if (listeners.size === 0) {
        this.streamEventHandlers.delete(event);
      }
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to remove server stream handler.")
      );
    }

    return this;
  }

  public use(middleware: SecureServerMiddleware): this {
    try {
      if (typeof middleware !== "function") {
        throw new Error("Server middleware must be a function.");
      }

      this.middlewareHandlers.push(middleware);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register server middleware.")
      );
    }

    return this;
  }

  public emit(event: string, data: unknown): this {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      this.emitLocally(event, data);
      this.publishAdapterMessage({
        scope: "broadcast",
        event,
        data
      });
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

  public async emitStreamTo(
    clientId: string,
    event: string,
    source: SecureChunkedStreamSource,
    options?: SecureChunkedStreamOptions
  ): Promise<SecureStreamSendResult> {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      const client = this.clientsById.get(clientId);

      if (!client) {
        throw new Error(`Client with id ${clientId} was not found.`);
      }

      if (!this.isClientHandshakeReady(client.socket)) {
        throw new Error(
          `Cannot stream event "${event}" before secure handshake completion for client ${client.id}.`
        );
      }

      return await transmitChunkedStreamFrames(
        event,
        source,
        options,
        async (framePayload) => {
          await this.sendEncryptedEnvelope(client.socket, {
            event: INTERNAL_STREAM_FRAME_EVENT,
            data: framePayload
          });
        }
      );
    } catch (error) {
      const normalizedError = normalizeToError(
        error,
        `Failed to emit chunked stream event "${event}" to client ${clientId}.`
      );

      this.notifyError(normalizedError);
      throw normalizedError;
    }
  }

  public to(room: string): SecureServerRoomOperator {
    const normalizedRoom = this.normalizeRoomName(room);

    return {
      emit: (event: string, data: unknown): SecureServer => {
        try {
          this.emitToRoom(normalizedRoom, event, data, true);
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

      const activeAdapter = this.adapter;
      this.adapter = null;

      if (activeAdapter?.detach) {
        void Promise.resolve(activeAdapter.detach(this)).catch((error) => {
          this.notifyError(
            normalizeToError(error, "Failed to detach SecureServer adapter during close.")
          );
        });
      }

      for (const client of this.clientsById.values()) {
        this.rejectPendingRpcRequests(
          client.socket,
          new Error("Server closed before ACK response was received.")
        );
        this.cleanupIncomingStreamsForSocket(
          client.socket,
          "Server closed before stream transfer completed."
        );
        this.middlewareMetadataBySocket.delete(client.socket);

        if (
          client.socket.readyState === WebSocket.OPEN ||
          client.socket.readyState === WebSocket.CONNECTING
        ) {
          client.socket.close(code, reason);
        }
      }

      this.rateLimitBucketsByClientId.clear();
      this.rateLimitBucketsByIp.clear();
      this.clientIpByClientId.clear();
      this.sessionTicketStore.clear();

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

  private resolveRateLimitConfig(
    rateLimitOptions: SecureServerRateLimitOptions | undefined
  ): Required<SecureServerRateLimitOptions> {
    const windowMs = rateLimitOptions?.windowMs ?? DEFAULT_RATE_LIMIT_WINDOW_MS;
    const maxEventsPerConnection =
      rateLimitOptions?.maxEventsPerConnection ??
      DEFAULT_RATE_LIMIT_MAX_EVENTS_PER_CONNECTION;
    const maxEventsPerIp =
      rateLimitOptions?.maxEventsPerIp ?? DEFAULT_RATE_LIMIT_MAX_EVENTS_PER_IP;
    const action = rateLimitOptions?.action ?? "throttle";
    const throttleMs = rateLimitOptions?.throttleMs ?? DEFAULT_RATE_LIMIT_THROTTLE_MS;
    const maxThrottleMs =
      rateLimitOptions?.maxThrottleMs ?? DEFAULT_RATE_LIMIT_MAX_THROTTLE_MS;
    const disconnectAfterViolations =
      rateLimitOptions?.disconnectAfterViolations ??
      DEFAULT_RATE_LIMIT_DISCONNECT_AFTER_VIOLATIONS;
    const disconnectCode =
      rateLimitOptions?.disconnectCode ?? DEFAULT_RATE_LIMIT_CLOSE_CODE;
    const disconnectReason =
      rateLimitOptions?.disconnectReason ?? DEFAULT_RATE_LIMIT_CLOSE_REASON;

    if (!Number.isFinite(windowMs) || windowMs <= 0) {
      throw new Error("Server rateLimit windowMs must be a positive number.");
    }

    if (!Number.isFinite(maxEventsPerConnection) || maxEventsPerConnection <= 0) {
      throw new Error(
        "Server rateLimit maxEventsPerConnection must be a positive number."
      );
    }

    if (!Number.isFinite(maxEventsPerIp) || maxEventsPerIp <= 0) {
      throw new Error("Server rateLimit maxEventsPerIp must be a positive number.");
    }

    if (action !== "throttle" && action !== "disconnect") {
      throw new Error('Server rateLimit action must be either "throttle" or "disconnect".');
    }

    if (!Number.isFinite(throttleMs) || throttleMs <= 0) {
      throw new Error("Server rateLimit throttleMs must be a positive number.");
    }

    if (!Number.isFinite(maxThrottleMs) || maxThrottleMs <= 0) {
      throw new Error("Server rateLimit maxThrottleMs must be a positive number.");
    }

    if (maxThrottleMs < throttleMs) {
      throw new Error(
        "Server rateLimit maxThrottleMs must be greater than or equal to throttleMs."
      );
    }

    if (
      !Number.isInteger(disconnectAfterViolations) ||
      disconnectAfterViolations <= 0
    ) {
      throw new Error(
        "Server rateLimit disconnectAfterViolations must be a positive integer."
      );
    }

    if (!Number.isInteger(disconnectCode) || disconnectCode < 1000 || disconnectCode > 4999) {
      throw new Error("Server rateLimit disconnectCode must be a valid WebSocket close code.");
    }

    return {
      enabled: rateLimitOptions?.enabled ?? true,
      windowMs,
      maxEventsPerConnection,
      maxEventsPerIp,
      action,
      throttleMs,
      maxThrottleMs,
      disconnectAfterViolations,
      disconnectCode,
      disconnectReason
    };
  }

  private resolveSessionResumptionConfig(
    sessionResumptionOptions: SecureServerSessionResumptionOptions | undefined
  ): Required<SecureServerSessionResumptionOptions> {
    const ticketTtlMs =
      sessionResumptionOptions?.ticketTtlMs ?? DEFAULT_SESSION_TICKET_TTL_MS;
    const maxCachedTickets =
      sessionResumptionOptions?.maxCachedTickets ??
      DEFAULT_SESSION_TICKET_MAX_CACHE_SIZE;

    if (!Number.isFinite(ticketTtlMs) || ticketTtlMs <= 0) {
      throw new Error(
        "Server sessionResumption ticketTtlMs must be a positive number."
      );
    }

    if (!Number.isInteger(maxCachedTickets) || maxCachedTickets <= 0) {
      throw new Error(
        "Server sessionResumption maxCachedTickets must be a positive integer."
      );
    }

    return {
      enabled:
        sessionResumptionOptions?.enabled ?? DEFAULT_SESSION_RESUMPTION_ENABLED,
      ticketTtlMs,
      maxCachedTickets
    };
  }

  private pruneExpiredSessionTickets(now: number): void {
    for (const [sessionId, ticketRecord] of this.sessionTicketStore.entries()) {
      if (ticketRecord.expiresAt <= now) {
        this.sessionTicketStore.delete(sessionId);
      }
    }
  }

  private evictSessionTicketsIfNeeded(): void {
    while (this.sessionTicketStore.size > this.sessionResumptionConfig.maxCachedTickets) {
      let oldestSessionId: string | null = null;
      let oldestIssuedAt = Number.POSITIVE_INFINITY;

      for (const [sessionId, ticketRecord] of this.sessionTicketStore.entries()) {
        if (ticketRecord.issuedAt < oldestIssuedAt) {
          oldestIssuedAt = ticketRecord.issuedAt;
          oldestSessionId = sessionId;
        }
      }

      if (!oldestSessionId) {
        break;
      }

      this.sessionTicketStore.delete(oldestSessionId);
    }
  }

  private getSessionTicket(sessionId: string): ServerSessionTicketRecord | null {
    const now = Date.now();
    this.pruneExpiredSessionTickets(now);

    const ticketRecord = this.sessionTicketStore.get(sessionId);

    if (!ticketRecord) {
      return null;
    }

    if (ticketRecord.expiresAt <= now) {
      this.sessionTicketStore.delete(sessionId);
      return null;
    }

    return ticketRecord;
  }

  private issueSessionTicket(socket: WebSocket, baseKey: Buffer): void {
    if (!this.sessionResumptionConfig.enabled) {
      return;
    }

    const now = Date.now();
    this.pruneExpiredSessionTickets(now);

    const sessionId = randomUUID();
    const sessionSecret = deriveSessionTicketSecret(baseKey);
    const expiresAt = now + this.sessionResumptionConfig.ticketTtlMs;

    const ticketRecord: ServerSessionTicketRecord = {
      sessionId,
      secret: sessionSecret,
      issuedAt: now,
      expiresAt
    };

    this.sessionTicketStore.set(sessionId, ticketRecord);
    this.evictSessionTicketsIfNeeded();

    const ticketPayload: SessionTicketPayload = {
      version: SESSION_TICKET_VERSION,
      sessionId,
      secret: sessionSecret.toString("base64"),
      issuedAt: now,
      expiresAt
    };

    void this.sendOrQueuePayload(socket, {
      event: INTERNAL_SESSION_TICKET_EVENT,
      data: ticketPayload
    }).catch((error) => {
      this.notifyError(
        normalizeToError(error, "Failed to deliver secure session ticket.")
      );
    });
  }

  private createRateLimitBucket(now: number): SecureServerRateLimitBucket {
    return {
      windowStartedAt: now,
      count: 0,
      violationCount: 0,
      throttleUntil: 0,
      lastSeenAt: now
    };
  }

  private getOrCreateRateLimitBucket(
    map: Map<string, SecureServerRateLimitBucket>,
    key: string,
    now: number
  ): SecureServerRateLimitBucket {
    const existingBucket = map.get(key);

    if (existingBucket) {
      return existingBucket;
    }

    const bucket = this.createRateLimitBucket(now);
    map.set(key, bucket);
    return bucket;
  }

  private updateRateLimitBucket(bucket: SecureServerRateLimitBucket, now: number): void {
    if (now - bucket.windowStartedAt >= this.rateLimitConfig.windowMs) {
      bucket.windowStartedAt = now;
      bucket.count = 0;
      bucket.violationCount = 0;
      bucket.throttleUntil = 0;
    }

    bucket.count += 1;
    bucket.lastSeenAt = now;
  }

  private pruneRateLimitBucketMap(
    map: Map<string, SecureServerRateLimitBucket>,
    now: number,
    maxIdleMs: number
  ): void {
    for (const [key, bucket] of map.entries()) {
      if (now - bucket.lastSeenAt >= maxIdleMs) {
        map.delete(key);
      }
    }
  }

  private pruneRateLimitBuckets(now: number): void {
    const maxIdleMs = this.rateLimitConfig.windowMs * 4;
    this.pruneRateLimitBucketMap(this.rateLimitBucketsByClientId, now, maxIdleMs);
    this.pruneRateLimitBucketMap(this.rateLimitBucketsByIp, now, maxIdleMs);
  }

  private normalizeIpAddress(ipAddress: string): string {
    let normalized = ipAddress.trim().toLowerCase();

    if (normalized.startsWith("::ffff:")) {
      normalized = normalized.slice(7);
    }

    if (normalized.startsWith("[") && normalized.endsWith("]")) {
      normalized = normalized.slice(1, -1);
    }

    const zoneIndex = normalized.indexOf("%");

    if (zoneIndex >= 0) {
      normalized = normalized.slice(0, zoneIndex);
    }

    return normalized.length > 0 ? normalized : "unknown";
  }

  private resolveClientIp(request: IncomingMessage): string {
    const forwardedHeader = request.headers["x-forwarded-for"];
    const forwardedValue = Array.isArray(forwardedHeader)
      ? forwardedHeader[0]
      : forwardedHeader;

    if (typeof forwardedValue === "string") {
      const firstForwardedIp = forwardedValue
        .split(",")
        .map((item) => item.trim())
        .find((item) => item.length > 0);

      if (firstForwardedIp) {
        return this.normalizeIpAddress(firstForwardedIp);
      }
    }

    return this.normalizeIpAddress(request.socket.remoteAddress ?? "unknown");
  }

  private isIpStillConnected(ipAddress: string): boolean {
    for (const connectedIp of this.clientIpByClientId.values()) {
      if (connectedIp === ipAddress) {
        return true;
      }
    }

    return false;
  }

  private evaluateIncomingRateLimit(
    client: SecureServerClient
  ): SecureServerRateLimitDecision {
    const noLimitDecision: SecureServerRateLimitDecision = {
      shouldDisconnect: false,
      shouldDrop: false,
      throttleDelayMs: 0
    };

    if (!this.rateLimitConfig.enabled) {
      return noLimitDecision;
    }

    const now = Date.now();
    const clientBucket = this.getOrCreateRateLimitBucket(
      this.rateLimitBucketsByClientId,
      client.id,
      now
    );

    this.updateRateLimitBucket(clientBucket, now);

    const clientIp = this.clientIpByClientId.get(client.id);
    const ipBucket = clientIp
      ? this.getOrCreateRateLimitBucket(this.rateLimitBucketsByIp, clientIp, now)
      : null;

    if (ipBucket) {
      this.updateRateLimitBucket(ipBucket, now);
    }

    const activeThrottleUntil = Math.max(
      clientBucket.throttleUntil,
      ipBucket?.throttleUntil ?? 0
    );

    if (activeThrottleUntil > now) {
      return {
        shouldDisconnect: false,
        shouldDrop: true,
        throttleDelayMs: 0
      };
    }

    const isConnectionLimitExceeded =
      clientBucket.count > this.rateLimitConfig.maxEventsPerConnection;
    const isIpLimitExceeded = ipBucket
      ? ipBucket.count > this.rateLimitConfig.maxEventsPerIp
      : false;

    if (!isConnectionLimitExceeded && !isIpLimitExceeded) {
      if (
        this.rateLimitBucketsByClientId.size > 1_024 ||
        this.rateLimitBucketsByIp.size > 1_024
      ) {
        this.pruneRateLimitBuckets(now);
      }

      return noLimitDecision;
    }

    if (isConnectionLimitExceeded) {
      clientBucket.violationCount += 1;
    }

    if (ipBucket && isIpLimitExceeded) {
      ipBucket.violationCount += 1;
    }

    const violationCount = Math.max(
      clientBucket.violationCount,
      ipBucket?.violationCount ?? 0
    );

    const shouldDisconnect =
      this.rateLimitConfig.action === "disconnect" ||
      violationCount >= this.rateLimitConfig.disconnectAfterViolations;

    if (shouldDisconnect) {
      return {
        shouldDisconnect: true,
        shouldDrop: true,
        throttleDelayMs: 0
      };
    }

    const throttleDelayMs = Math.min(
      this.rateLimitConfig.maxThrottleMs,
      Math.max(
        this.rateLimitConfig.throttleMs,
        this.rateLimitConfig.throttleMs * violationCount
      )
    );

    const throttleUntil = now + throttleDelayMs;
    clientBucket.throttleUntil = throttleUntil;

    if (ipBucket) {
      ipBucket.throttleUntil = throttleUntil;
    }

    return {
      shouldDisconnect: false,
      shouldDrop: false,
      throttleDelayMs
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
        this.middlewareMetadataBySocket.delete(socket);
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
      void this.handleConnection(socket, request);
    });

    this.socketServer.on("error", (error: Error) => {
      this.notifyError(normalizeToError(error, "WebSocket server encountered an error."));
    });
  }

  private async handleConnection(socket: WebSocket, request: IncomingMessage): Promise<void> {
    const connectionMetadata = new Map<string, unknown>();
    this.middlewareMetadataBySocket.set(socket, connectionMetadata);

    try {
      await this.executeServerMiddleware({
        phase: "connection",
        socket,
        request,
        metadata: connectionMetadata
      });
    } catch (error) {
      const normalizedError = normalizeToError(
        error,
        "Connection middleware rejected the incoming socket."
      );

      this.notifyError(normalizedError);
      this.middlewareMetadataBySocket.delete(socket);

      if (
        socket.readyState === WebSocket.OPEN ||
        socket.readyState === WebSocket.CONNECTING
      ) {
        socket.close(
          POLICY_VIOLATION_CLOSE_CODE,
          normalizedError.message || POLICY_VIOLATION_CLOSE_REASON
        );
      }

      return;
    }

    try {
      const clientId = randomUUID();
      const handshakeState = this.createServerHandshakeState();
      const clientIp = this.resolveClientIp(request);

      connectionMetadata.set("network.ip", clientIp);

      const client = this.createSecureServerClient(
        clientId,
        socket,
        request,
        connectionMetadata
      );

      this.clientsById.set(clientId, client);
      this.clientIdBySocket.set(socket, clientId);
      this.clientIpByClientId.set(clientId, clientIp);
      this.handshakeStateBySocket.set(socket, handshakeState);
      this.pendingPayloadsBySocket.set(socket, []);
      this.pendingRpcRequestsBySocket.set(socket, new Map<string, PendingRpcRequest>());
      this.heartbeatStateBySocket.set(socket, {
        awaitingPong: false,
        lastPingAt: 0
      });
      this.roomNamesByClientId.set(clientId, new Set<string>());

      socket.on("message", (rawData: RawData) => {
        void this.handleIncomingMessage(client, rawData);
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
      this.middlewareMetadataBySocket.delete(socket);
    }
  }

  private async handleIncomingMessage(
    client: SecureServerClient,
    rawData: RawData
  ): Promise<void> {
    try {
      const rateLimitDecision = this.evaluateIncomingRateLimit(client);

      if (rateLimitDecision.shouldDisconnect) {
        this.notifyError(
          new Error(
            `Rate limit disconnect triggered for client ${client.id}.`
          )
        );

        if (
          client.socket.readyState === WebSocket.OPEN ||
          client.socket.readyState === WebSocket.CONNECTING
        ) {
          client.socket.close(
            this.rateLimitConfig.disconnectCode,
            this.rateLimitConfig.disconnectReason
          );
        }

        return;
      }

      if (rateLimitDecision.shouldDrop) {
        return;
      }

      if (rateLimitDecision.throttleDelayMs > 0) {
        this.notifyError(
          new Error(
            `Rate limit throttle applied to client ${client.id} for ${rateLimitDecision.throttleDelayMs}ms.`
          )
        );

        await delay(rateLimitDecision.throttleDelayMs);

        if (client.socket.readyState !== WebSocket.OPEN) {
          return;
        }
      }

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
        await this.handleRpcRequest(client, decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_STREAM_FRAME_EVENT) {
        this.handleIncomingStreamFrame(client, decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_SESSION_TICKET_EVENT) {
        this.notifyError(
          new Error(
            `Client ${client.id} attempted to send reserved internal session ticket event.`
          )
        );
        return;
      }

      const interceptedData = await this.applyMessageMiddleware(
        "incoming",
        client,
        decryptedEnvelope.event,
        decryptedEnvelope.data
      );

      this.dispatchCustomEvent(decryptedEnvelope.event, interceptedData, client);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process incoming server message."));
    }
  }

  private handleDisconnection(client: SecureServerClient, code: number, reason: Buffer): void {
    try {
      client.leaveAll();
      this.clientsById.delete(client.id);
      this.clientIdBySocket.delete(client.socket);

      const disconnectedIp = this.clientIpByClientId.get(client.id);

      this.clientIpByClientId.delete(client.id);
      this.rateLimitBucketsByClientId.delete(client.id);

      if (disconnectedIp && !this.isIpStillConnected(disconnectedIp)) {
        this.rateLimitBucketsByIp.delete(disconnectedIp);
      }

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
      this.middlewareMetadataBySocket.delete(client.socket);
      this.cleanupIncomingStreamsForSocket(
        client.socket,
        `Client ${client.id} disconnected before stream transfer completed.`
      );

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

  private getOrCreateIncomingServerStreams(
    socket: WebSocket
  ): Map<string, IncomingServerStreamState> {
    const existingStreams = this.incomingStreamsBySocket.get(socket);

    if (existingStreams) {
      return existingStreams;
    }

    const streamMap = new Map<string, IncomingServerStreamState>();
    this.incomingStreamsBySocket.set(socket, streamMap);
    return streamMap;
  }

  private cleanupIncomingStreamsForSocket(socket: WebSocket, reason: string): void {
    const streamMap = this.incomingStreamsBySocket.get(socket);

    if (!streamMap) {
      return;
    }

    for (const streamState of streamMap.values()) {
      streamState.stream.destroy(new Error(reason));
    }

    streamMap.clear();
    this.incomingStreamsBySocket.delete(socket);
  }

  private abortIncomingServerStream(
    socket: WebSocket,
    streamId: string,
    reason: string
  ): void {
    const streamMap = this.incomingStreamsBySocket.get(socket);

    if (!streamMap) {
      return;
    }

    const streamState = streamMap.get(streamId);

    if (!streamState) {
      return;
    }

    streamState.stream.destroy(new Error(reason));
    streamMap.delete(streamId);

    if (streamMap.size === 0) {
      this.incomingStreamsBySocket.delete(socket);
    }
  }

  private dispatchServerStreamEvent(
    event: string,
    stream: Readable,
    info: SecureIncomingStreamInfo,
    client: SecureServerClient
  ): void {
    const handlers = this.streamEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      stream.resume();
      this.notifyError(
        new Error(
          `No stream handler is registered for event "${event}" on server client ${client.id}.`
        )
      );
      return;
    }

    for (const handler of handlers) {
      try {
        const handlerResult = handler(stream, info, client);

        if (isPromiseLike(handlerResult)) {
          void Promise.resolve(handlerResult).catch((error) => {
            this.notifyError(
              normalizeToError(
                error,
                `Server stream handler failed for event ${event}.`
              )
            );
          });
        }
      } catch (error) {
        this.notifyError(
          normalizeToError(
            error,
            `Server stream handler failed for event ${event}.`
          )
        );
      }
    }
  }

  private handleIncomingStreamStartFrame(
    client: SecureServerClient,
    framePayload: StreamFrameStartPayload
  ): void {
    if (isReservedEmitEvent(framePayload.event)) {
      throw new Error(
        `Reserved event "${framePayload.event}" cannot be used for stream transport.`
      );
    }

    const incomingStreams = this.getOrCreateIncomingServerStreams(client.socket);

    if (incomingStreams.has(framePayload.streamId)) {
      throw new Error(
        `Stream ${framePayload.streamId} already exists for client ${client.id}.`
      );
    }

    const stream = new PassThrough();
    const streamInfo: SecureIncomingStreamInfo = {
      streamId: framePayload.streamId,
      event: framePayload.event,
      startedAt: Date.now(),
      ...(framePayload.metadata !== undefined ? { metadata: framePayload.metadata } : {}),
      ...(framePayload.totalBytes !== undefined ? { totalBytes: framePayload.totalBytes } : {})
    };

    incomingStreams.set(framePayload.streamId, {
      info: streamInfo,
      stream,
      expectedChunkIndex: 0,
      receivedBytes: 0
    });

    this.dispatchServerStreamEvent(framePayload.event, stream, streamInfo, client);
  }

  private handleIncomingStreamChunkFrame(
    client: SecureServerClient,
    framePayload: StreamFrameChunkPayload
  ): void {
    const incomingStreams = this.incomingStreamsBySocket.get(client.socket);
    const streamState = incomingStreams?.get(framePayload.streamId);

    if (!incomingStreams || !streamState) {
      throw new Error(
        `Stream ${framePayload.streamId} is unknown for client ${client.id}.`
      );
    }

    if (framePayload.index !== streamState.expectedChunkIndex) {
      throw new Error(
        `Out-of-order chunk index for stream ${framePayload.streamId}. Expected ${streamState.expectedChunkIndex}, received ${framePayload.index}.`
      );
    }

    const chunkBuffer = decodeBase64ToBuffer(
      framePayload.payload,
      `Stream chunk payload (${framePayload.streamId})`
    );

    if (chunkBuffer.length !== framePayload.byteLength) {
      throw new Error(
        `Stream ${framePayload.streamId} byteLength mismatch. Expected ${framePayload.byteLength}, received ${chunkBuffer.length}.`
      );
    }

    streamState.expectedChunkIndex += 1;
    streamState.receivedBytes += chunkBuffer.length;
    streamState.stream.write(chunkBuffer);
  }

  private handleIncomingStreamEndFrame(
    client: SecureServerClient,
    framePayload: StreamFrameEndPayload
  ): void {
    const incomingStreams = this.incomingStreamsBySocket.get(client.socket);
    const streamState = incomingStreams?.get(framePayload.streamId);

    if (!incomingStreams || !streamState) {
      throw new Error(
        `Stream ${framePayload.streamId} is unknown for client ${client.id}.`
      );
    }

    if (framePayload.chunkCount !== streamState.expectedChunkIndex) {
      throw new Error(
        `Stream ${framePayload.streamId} chunkCount mismatch. Expected ${streamState.expectedChunkIndex}, received ${framePayload.chunkCount}.`
      );
    }

    if (framePayload.totalBytes !== streamState.receivedBytes) {
      throw new Error(
        `Stream ${framePayload.streamId} totalBytes mismatch. Expected ${streamState.receivedBytes}, received ${framePayload.totalBytes}.`
      );
    }

    if (
      streamState.info.totalBytes !== undefined &&
      streamState.info.totalBytes !== streamState.receivedBytes
    ) {
      throw new Error(
        `Stream ${framePayload.streamId} violated announced totalBytes (${streamState.info.totalBytes}).`
      );
    }

    streamState.stream.end();
    incomingStreams.delete(framePayload.streamId);

    if (incomingStreams.size === 0) {
      this.incomingStreamsBySocket.delete(client.socket);
    }
  }

  private handleIncomingStreamAbortFrame(
    client: SecureServerClient,
    framePayload: StreamFrameAbortPayload
  ): void {
    this.abortIncomingServerStream(
      client.socket,
      framePayload.streamId,
      framePayload.reason
    );
  }

  private handleIncomingStreamFrame(client: SecureServerClient, data: unknown): void {
    let framePayload: StreamFramePayload | null = null;

    try {
      framePayload = parseStreamFramePayload(data);

      if (framePayload.type === "start") {
        this.handleIncomingStreamStartFrame(client, framePayload);
        return;
      }

      if (framePayload.type === "chunk") {
        this.handleIncomingStreamChunkFrame(client, framePayload);
        return;
      }

      if (framePayload.type === "end") {
        this.handleIncomingStreamEndFrame(client, framePayload);
        return;
      }

      this.handleIncomingStreamAbortFrame(client, framePayload);
    } catch (error) {
      const normalizedError = normalizeToError(
        error,
        `Failed to process incoming stream frame for client ${client.id}.`
      );

      if (framePayload) {
        this.abortIncomingServerStream(
          client.socket,
          framePayload.streamId,
          normalizedError.message
        );
      }

      this.notifyError(normalizedError);
    }
  }

  private async executeServerMiddleware(
    context: SecureServerMiddlewareContext
  ): Promise<void> {
    if (this.middlewareHandlers.length === 0) {
      return;
    }

    let currentIndex = -1;

    const dispatch = async (index: number): Promise<void> => {
      if (index <= currentIndex) {
        throw new Error("Server middleware next() was called multiple times.");
      }

      currentIndex = index;
      const middleware = this.middlewareHandlers[index];

      if (!middleware) {
        return;
      }

      await Promise.resolve(
        middleware(context, async () => {
          await dispatch(index + 1);
        })
      );
    };

    await dispatch(0);
  }

  private async applyMessageMiddleware(
    phase: "incoming" | "outgoing",
    client: SecureServerClient,
    event: string,
    data: unknown
  ): Promise<unknown> {
    const metadata =
      this.middlewareMetadataBySocket.get(client.socket) ?? new Map<string, unknown>();

    this.middlewareMetadataBySocket.set(client.socket, metadata);

    const middlewareContext: SecureServerMessageMiddlewareContext = {
      phase,
      client,
      event,
      data,
      metadata
    };

    await this.executeServerMiddleware(middlewareContext);
    return middlewareContext.data;
  }

  private resolveClientBySocket(socket: WebSocket): SecureServerClient | null {
    const clientId = this.clientIdBySocket.get(socket);

    if (!clientId) {
      return null;
    }

    return this.clientsById.get(clientId) ?? null;
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
      const interceptedData = await this.applyMessageMiddleware(
        "incoming",
        client,
        rpcRequestPayload.event,
        rpcRequestPayload.data
      );

      const ackResponse = await this.executeRpcRequestHandler(
        rpcRequestPayload.event,
        interceptedData,
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
        type: "hello",
        protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
        publicKey: localPublicKey
      })
    );
  }

  private sendResumeAck(
    socket: WebSocket,
    payload: {
      ok: boolean;
      sessionId?: string;
      serverProof?: string;
      reason?: string;
    }
  ): void {
    const responsePayload: HandshakeResumeAckPayload = {
      type: "resume-ack",
      protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
      ok: payload.ok
    };

    if (payload.sessionId !== undefined && payload.sessionId.length > 0) {
      responsePayload.sessionId = payload.sessionId;
    }

    if (payload.serverProof !== undefined && payload.serverProof.length > 0) {
      responsePayload.serverProof = payload.serverProof;
    }

    if (payload.reason !== undefined && payload.reason.length > 0) {
      responsePayload.reason = payload.reason;
    }

    this.sendRaw(
      socket,
      serializePlainEnvelope(INTERNAL_HANDSHAKE_EVENT, responsePayload)
    );
  }

  private handleResumeHandshake(
    client: SecureServerClient,
    payload: HandshakeResumePayload
  ): void {
    if (!this.sessionResumptionConfig.enabled) {
      this.sendResumeAck(client.socket, {
        ok: false,
        reason: "Session resumption is disabled."
      });
      return;
    }

    const ticketRecord = this.getSessionTicket(payload.sessionId);

    if (!ticketRecord) {
      this.sendResumeAck(client.socket, {
        ok: false,
        reason: "Session ticket is unknown or expired."
      });
      return;
    }

    try {
      const clientNonce = decodeBase64ToBuffer(
        payload.clientNonce,
        "Handshake resume clientNonce"
      );

      if (clientNonce.length !== RESUMPTION_NONCE_LENGTH) {
        throw new Error(
          `Handshake resume clientNonce must be ${RESUMPTION_NONCE_LENGTH} bytes.`
        );
      }

      const receivedProof = decodeBase64ToBuffer(
        payload.clientProof,
        "Handshake resume clientProof"
      );

      const expectedProof = createResumeClientProof(
        ticketRecord.secret,
        ticketRecord.sessionId,
        clientNonce
      );

      if (!equalsConstantTime(receivedProof, expectedProof)) {
        this.sendResumeAck(client.socket, {
          ok: false,
          reason: "Session resumption proof validation failed."
        });
        return;
      }

      this.sessionTicketStore.delete(ticketRecord.sessionId);

      const resumedKey = deriveResumedEncryptionKey(ticketRecord.secret, clientNonce);
      const serverProof = createResumeServerProof(
        resumedKey,
        ticketRecord.sessionId,
        clientNonce
      ).toString("base64");
      const handshakeState = this.handshakeStateBySocket.get(client.socket);

      if (!handshakeState) {
        throw new Error(`Missing handshake state for client ${client.id}.`);
      }

      this.sharedSecretBySocket.set(client.socket, resumedKey);
      this.encryptionKeyBySocket.set(client.socket, resumedKey);
      handshakeState.isReady = true;

      this.sendResumeAck(client.socket, {
        ok: true,
        sessionId: ticketRecord.sessionId,
        serverProof
      });

      void this.flushQueuedPayloads(client.socket);
      this.notifyReady(client);
      this.issueSessionTicket(client.socket, resumedKey);
    } catch (error) {
      this.sendResumeAck(client.socket, {
        ok: false,
        reason: "Session resumption payload was invalid."
      });

      this.notifyError(normalizeToError(error, "Failed to resume secure server session."));
    }
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

      if (payload.type === "resume") {
        this.handleResumeHandshake(client, payload);
        return;
      }

      if (payload.type === "resume-ack") {
        throw new Error("SecureServer received unexpected resume-ack handshake payload.");
      }

      const remotePublicKey = Buffer.from(payload.publicKey, "base64");
      const sharedSecret = handshakeState.ecdh.computeSecret(remotePublicKey);
      const encryptionKey = deriveEncryptionKey(sharedSecret);

      this.sharedSecretBySocket.set(client.socket, sharedSecret);
      this.encryptionKeyBySocket.set(client.socket, encryptionKey);
      handshakeState.isReady = true;

      void this.flushQueuedPayloads(client.socket);
      this.notifyReady(client);
      this.issueSessionTicket(client.socket, encryptionKey);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to complete server handshake."));
    }
  }

  private isClientHandshakeReady(socket: WebSocket): boolean {
    return this.handshakeStateBySocket.get(socket)?.isReady ?? false;
  }

  private async sendOrQueuePayload(
    socket: WebSocket,
    envelope: SecureEnvelope
  ): Promise<void> {
    let interceptedEnvelope = envelope;

    if (!isReservedEmitEvent(envelope.event)) {
      const targetClient = this.resolveClientBySocket(socket);

      if (targetClient) {
        const interceptedData = await this.applyMessageMiddleware(
          "outgoing",
          targetClient,
          envelope.event,
          envelope.data
        );

        interceptedEnvelope = {
          event: envelope.event,
          data: interceptedData
        };
      }
    }

    if (!this.isClientHandshakeReady(socket)) {
      this.queuePayload(socket, interceptedEnvelope);
      return;
    }

    await this.sendEncryptedEnvelope(socket, interceptedEnvelope);
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
    request: IncomingMessage,
    metadata: Map<string, unknown>
  ): SecureServerClient {
    return {
      id: clientId,
      socket,
      request,
      metadata,
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
      emitStream: (
        event: string,
        source: SecureChunkedStreamSource,
        options?: SecureChunkedStreamOptions
      ): Promise<SecureStreamSendResult> => {
        return this.emitStreamTo(clientId, event, source, options);
      },
      join: (room: string): boolean => this.joinClientToRoom(clientId, room),
      leave: (room: string): boolean => this.leaveClientFromRoom(clientId, room),
      leaveAll: (): number => this.leaveClientFromAllRooms(clientId)
    };
  }

  private emitLocally(event: string, data: unknown): void {
    const envelope: SecureEnvelope = { event, data };

    for (const client of this.clientsById.values()) {
      void this.sendOrQueuePayload(client.socket, envelope).catch(() => {
        return undefined;
      });
    }
  }

  private publishAdapterMessage(
    message: Omit<SecureServerAdapterMessage, "version" | "originServerId" | "emittedAt">
  ): void {
    if (!this.adapter) {
      return;
    }

    let adapterMessage: SecureServerAdapterMessage;

    if (message.scope === "room") {
      if (!message.room) {
        return;
      }

      adapterMessage = {
        version: SECURE_SERVER_ADAPTER_MESSAGE_VERSION,
        originServerId: this.instanceId,
        scope: "room",
        event: message.event,
        data: message.data,
        emittedAt: Date.now(),
        room: message.room
      };
    } else {
      adapterMessage = {
        version: SECURE_SERVER_ADAPTER_MESSAGE_VERSION,
        originServerId: this.instanceId,
        scope: "broadcast",
        event: message.event,
        data: message.data,
        emittedAt: Date.now()
      };
    }

    void Promise.resolve(this.adapter.publish(adapterMessage)).catch((error) => {
      this.notifyError(
        normalizeToError(error, "Failed to publish SecureServer adapter message.")
      );
    });
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

  private emitToRoom(
    room: string,
    event: string,
    data: unknown,
    replicate: boolean
  ): void {
    if (isReservedEmitEvent(event)) {
      throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
    }

    const roomMembers = this.roomMembersByName.get(room);

    if (roomMembers && roomMembers.size > 0) {
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

    if (replicate) {
      this.publishAdapterMessage({
        scope: "room",
        room,
        event,
        data
      });
    }
  }
}

export class SecureClient {
  private socket: WebSocket | null = null;

  private readonly reconnectConfig: Required<SecureClientReconnectOptions>;

  private readonly sessionResumptionConfig: Required<SecureClientSessionResumptionOptions>;

  private reconnectAttemptCount = 0;

  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  private isManualDisconnectRequested = false;

  private readonly customEventHandlers = new Map<string, Set<SecureClientEventHandler>>();

  private readonly streamEventHandlers = new Map<string, Set<SecureClientStreamHandler>>();

  private readonly connectHandlers = new Set<SecureClientConnectHandler>();

  private readonly disconnectHandlers = new Set<SecureClientDisconnectHandler>();

  private readonly readyHandlers = new Set<SecureClientReadyHandler>();

  private readonly errorHandlers = new Set<SecureErrorHandler>();

  private handshakeState: ClientHandshakeState | null = null;

  private pendingPayloadQueue: SecureEnvelope[] = [];

  private readonly pendingRpcRequests = new Map<string, PendingRpcRequest>();

  private readonly incomingStreams = new Map<string, IncomingClientStreamState>();

  private sessionTicket: ClientSessionTicketRecord | null = null;

  public constructor(
    private readonly url: string,
    private readonly options: SecureClientOptions = {}
  ) {
    this.reconnectConfig = this.resolveReconnectConfig(this.options.reconnect);
    this.sessionResumptionConfig = this.resolveSessionResumptionConfig(
      this.options.sessionResumption
    );

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

      if (event === INTERNAL_HANDSHAKE_EVENT || event === INTERNAL_SESSION_TICKET_EVENT) {
        throw new Error(`The event "${event}" is reserved for internal use.`);
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

      if (event === INTERNAL_HANDSHAKE_EVENT || event === INTERNAL_SESSION_TICKET_EVENT) {
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

  public onStream(event: string, handler: SecureClientStreamHandler): this {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be used as a stream event.`);
      }

      const listeners = this.streamEventHandlers.get(event) ?? new Set<SecureClientStreamHandler>();
      listeners.add(handler);
      this.streamEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register client stream handler.")
      );
    }

    return this;
  }

  public offStream(event: string, handler: SecureClientStreamHandler): this {
    try {
      const listeners = this.streamEventHandlers.get(event);

      if (!listeners) {
        return this;
      }

      listeners.delete(handler);

      if (listeners.size === 0) {
        this.streamEventHandlers.delete(event);
      }
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to remove client stream handler.")
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

  public async emitStream(
    event: string,
    source: SecureChunkedStreamSource,
    options?: SecureChunkedStreamOptions
  ): Promise<SecureStreamSendResult> {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Client socket is not connected.");
      }

      if (!this.isHandshakeReady()) {
        throw new Error(
          `Cannot stream event "${event}" before secure handshake completion.`
        );
      }

      return await transmitChunkedStreamFrames(
        event,
        source,
        options,
        async (framePayload) => {
          await this.sendEncryptedEnvelope({
            event: INTERNAL_STREAM_FRAME_EVENT,
            data: framePayload
          });
        }
      );
    } catch (error) {
      const normalizedError = normalizeToError(
        error,
        `Failed to emit chunked stream event "${event}".`
      );

      this.notifyError(normalizedError);
      throw normalizedError;
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

  private resolveSessionResumptionConfig(
    sessionResumptionOptions: boolean | SecureClientSessionResumptionOptions | undefined
  ): Required<SecureClientSessionResumptionOptions> {
    if (typeof sessionResumptionOptions === "boolean") {
      return {
        enabled: sessionResumptionOptions,
        maxAcceptedTicketTtlMs: DEFAULT_SESSION_TICKET_TTL_MS
      };
    }

    const maxAcceptedTicketTtlMs =
      sessionResumptionOptions?.maxAcceptedTicketTtlMs ??
      DEFAULT_SESSION_TICKET_TTL_MS;

    if (!Number.isFinite(maxAcceptedTicketTtlMs) || maxAcceptedTicketTtlMs <= 0) {
      throw new Error(
        "Client sessionResumption maxAcceptedTicketTtlMs must be a positive number."
      );
    }

    return {
      enabled:
        sessionResumptionOptions?.enabled ?? DEFAULT_SESSION_RESUMPTION_ENABLED,
      maxAcceptedTicketTtlMs
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

      if (decryptedEnvelope.event === INTERNAL_STREAM_FRAME_EVENT) {
        this.handleIncomingStreamFrame(decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_SESSION_TICKET_EVENT) {
        this.handleSessionTicket(decryptedEnvelope.data);
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
      this.cleanupIncomingStreams(
        "Client disconnected before stream transfer completed."
      );
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

  private cleanupIncomingStreams(reason: string): void {
    for (const streamState of this.incomingStreams.values()) {
      streamState.stream.destroy(new Error(reason));
    }

    this.incomingStreams.clear();
  }

  private abortIncomingClientStream(streamId: string, reason: string): void {
    const streamState = this.incomingStreams.get(streamId);

    if (!streamState) {
      return;
    }

    streamState.stream.destroy(new Error(reason));
    this.incomingStreams.delete(streamId);
  }

  private dispatchClientStreamEvent(
    event: string,
    stream: Readable,
    info: SecureIncomingStreamInfo
  ): void {
    const handlers = this.streamEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      stream.resume();
      this.notifyError(
        new Error(`No stream handler is registered for event "${event}" on client.`)
      );
      return;
    }

    for (const handler of handlers) {
      try {
        const handlerResult = handler(stream, info);

        if (isPromiseLike(handlerResult)) {
          void Promise.resolve(handlerResult).catch((error) => {
            this.notifyError(
              normalizeToError(
                error,
                `Client stream handler failed for event ${event}.`
              )
            );
          });
        }
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Client stream handler failed for event ${event}.`)
        );
      }
    }
  }

  private handleIncomingClientStreamStartFrame(framePayload: StreamFrameStartPayload): void {
    if (isReservedEmitEvent(framePayload.event)) {
      throw new Error(
        `Reserved event "${framePayload.event}" cannot be used for stream transport.`
      );
    }

    if (this.incomingStreams.has(framePayload.streamId)) {
      throw new Error(`Stream ${framePayload.streamId} already exists on client.`);
    }

    const stream = new PassThrough();
    const streamInfo: SecureIncomingStreamInfo = {
      streamId: framePayload.streamId,
      event: framePayload.event,
      startedAt: Date.now(),
      ...(framePayload.metadata !== undefined ? { metadata: framePayload.metadata } : {}),
      ...(framePayload.totalBytes !== undefined ? { totalBytes: framePayload.totalBytes } : {})
    };

    this.incomingStreams.set(framePayload.streamId, {
      info: streamInfo,
      stream,
      expectedChunkIndex: 0,
      receivedBytes: 0
    });

    this.dispatchClientStreamEvent(framePayload.event, stream, streamInfo);
  }

  private handleIncomingClientStreamChunkFrame(framePayload: StreamFrameChunkPayload): void {
    const streamState = this.incomingStreams.get(framePayload.streamId);

    if (!streamState) {
      throw new Error(`Stream ${framePayload.streamId} is unknown on client.`);
    }

    if (framePayload.index !== streamState.expectedChunkIndex) {
      throw new Error(
        `Out-of-order chunk index for stream ${framePayload.streamId}. Expected ${streamState.expectedChunkIndex}, received ${framePayload.index}.`
      );
    }

    const chunkBuffer = decodeBase64ToBuffer(
      framePayload.payload,
      `Stream chunk payload (${framePayload.streamId})`
    );

    if (chunkBuffer.length !== framePayload.byteLength) {
      throw new Error(
        `Stream ${framePayload.streamId} byteLength mismatch. Expected ${framePayload.byteLength}, received ${chunkBuffer.length}.`
      );
    }

    streamState.expectedChunkIndex += 1;
    streamState.receivedBytes += chunkBuffer.length;
    streamState.stream.write(chunkBuffer);
  }

  private handleIncomingClientStreamEndFrame(framePayload: StreamFrameEndPayload): void {
    const streamState = this.incomingStreams.get(framePayload.streamId);

    if (!streamState) {
      throw new Error(`Stream ${framePayload.streamId} is unknown on client.`);
    }

    if (framePayload.chunkCount !== streamState.expectedChunkIndex) {
      throw new Error(
        `Stream ${framePayload.streamId} chunkCount mismatch. Expected ${streamState.expectedChunkIndex}, received ${framePayload.chunkCount}.`
      );
    }

    if (framePayload.totalBytes !== streamState.receivedBytes) {
      throw new Error(
        `Stream ${framePayload.streamId} totalBytes mismatch. Expected ${streamState.receivedBytes}, received ${framePayload.totalBytes}.`
      );
    }

    if (
      streamState.info.totalBytes !== undefined &&
      streamState.info.totalBytes !== streamState.receivedBytes
    ) {
      throw new Error(
        `Stream ${framePayload.streamId} violated announced totalBytes (${streamState.info.totalBytes}).`
      );
    }

    streamState.stream.end();
    this.incomingStreams.delete(framePayload.streamId);
  }

  private handleIncomingClientStreamAbortFrame(framePayload: StreamFrameAbortPayload): void {
    this.abortIncomingClientStream(framePayload.streamId, framePayload.reason);
  }

  private handleIncomingStreamFrame(data: unknown): void {
    let framePayload: StreamFramePayload | null = null;

    try {
      framePayload = parseStreamFramePayload(data);

      if (framePayload.type === "start") {
        this.handleIncomingClientStreamStartFrame(framePayload);
        return;
      }

      if (framePayload.type === "chunk") {
        this.handleIncomingClientStreamChunkFrame(framePayload);
        return;
      }

      if (framePayload.type === "end") {
        this.handleIncomingClientStreamEndFrame(framePayload);
        return;
      }

      this.handleIncomingClientStreamAbortFrame(framePayload);
    } catch (error) {
      const normalizedError = normalizeToError(
        error,
        "Failed to process incoming stream frame on client."
      );

      if (framePayload) {
        this.abortIncomingClientStream(framePayload.streamId, normalizedError.message);
      }

      this.notifyError(normalizedError);
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

  private handleSessionTicket(data: unknown): void {
    if (!this.sessionResumptionConfig.enabled) {
      return;
    }

    try {
      const ticketPayload = parseSessionTicketPayload(data);
      const now = Date.now();

      if (ticketPayload.expiresAt <= now) {
        return;
      }

      const ticketTtlMs = ticketPayload.expiresAt - ticketPayload.issuedAt;

      if (ticketTtlMs > this.sessionResumptionConfig.maxAcceptedTicketTtlMs) {
        throw new Error("Session ticket TTL exceeds client trust policy.");
      }

      const sessionSecret = decodeBase64ToBuffer(
        ticketPayload.secret,
        "Session ticket secret"
      );

      if (sessionSecret.length !== ENCRYPTION_KEY_LENGTH) {
        throw new Error("Session ticket secret has invalid length.");
      }

      this.sessionTicket = {
        sessionId: ticketPayload.sessionId,
        secret: sessionSecret,
        issuedAt: ticketPayload.issuedAt,
        expiresAt: ticketPayload.expiresAt
      };
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process session ticket payload."));
    }
  }

  private createClientHandshakeState(): ClientHandshakeState {
    const { ecdh, localPublicKey } = createEphemeralHandshakeState();

    return {
      ecdh,
      localPublicKey,
      clientHelloSent: false,
      pendingServerPublicKey: null,
      resumeAttempt: null,
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

      if (this.handshakeState.clientHelloSent) {
        return;
      }

      this.socket.send(
        serializePlainEnvelope(INTERNAL_HANDSHAKE_EVENT, {
          type: "hello",
          protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
          publicKey: this.handshakeState.localPublicKey
        })
      );

      this.handshakeState.clientHelloSent = true;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send client handshake payload."));
    }
  }

  private shouldAttemptSessionResumption(): boolean {
    if (!this.sessionResumptionConfig.enabled) {
      return false;
    }

    const sessionTicket = this.sessionTicket;

    if (!sessionTicket) {
      return false;
    }

    const now = Date.now();

    if (sessionTicket.expiresAt <= now) {
      this.sessionTicket = null;
      return false;
    }

    const ticketTtlMs = sessionTicket.expiresAt - sessionTicket.issuedAt;

    if (ticketTtlMs > this.sessionResumptionConfig.maxAcceptedTicketTtlMs) {
      this.sessionTicket = null;
      return false;
    }

    return true;
  }

  private sendResumeHandshake(): boolean {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      return false;
    }

    if (!this.handshakeState || !this.sessionTicket) {
      return false;
    }

    if (this.handshakeState.clientHelloSent) {
      return false;
    }

    if (this.handshakeState.resumeAttempt?.status === "pending") {
      return true;
    }

    try {
      const clientNonce = randomBytes(RESUMPTION_NONCE_LENGTH);
      const resumedKey = deriveResumedEncryptionKey(this.sessionTicket.secret, clientNonce);
      const clientProof = createResumeClientProof(
        this.sessionTicket.secret,
        this.sessionTicket.sessionId,
        clientNonce
      );

      this.socket.send(
        serializePlainEnvelope(INTERNAL_HANDSHAKE_EVENT, {
          type: "resume",
          protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
          sessionId: this.sessionTicket.sessionId,
          clientNonce: clientNonce.toString("base64"),
          clientProof: clientProof.toString("base64")
        } satisfies HandshakeResumePayload)
      );

      this.handshakeState.resumeAttempt = {
        status: "pending",
        sessionId: this.sessionTicket.sessionId,
        clientNonce,
        resumedKey
      };

      return true;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to dispatch resume handshake payload."));
      this.sessionTicket = null;
      this.handshakeState.resumeAttempt = null;
      return false;
    }
  }

  private completeFullHandshake(serverPublicKey: string): void {
    if (!this.handshakeState) {
      throw new Error("Missing client handshake state.");
    }

    if (this.handshakeState.isReady) {
      return;
    }

    this.sendInternalHandshake();

    const remotePublicKey = Buffer.from(serverPublicKey, "base64");
    const sharedSecret = this.handshakeState.ecdh.computeSecret(remotePublicKey);

    this.handshakeState.sharedSecret = sharedSecret;
    this.handshakeState.encryptionKey = deriveEncryptionKey(sharedSecret);
    this.handshakeState.resumeAttempt = null;
    this.handshakeState.pendingServerPublicKey = null;
    this.handshakeState.isReady = true;

    void this.flushPendingPayloadQueue();
    this.notifyReady();
  }

  private fallbackToFullHandshake(): void {
    if (!this.handshakeState || this.handshakeState.isReady) {
      return;
    }

    if (this.handshakeState.resumeAttempt) {
      this.handshakeState.resumeAttempt.status = "failed";
    }

    const pendingServerPublicKey = this.handshakeState.pendingServerPublicKey;

    if (pendingServerPublicKey) {
      this.completeFullHandshake(pendingServerPublicKey);
      return;
    }

    this.sendInternalHandshake();
  }

  private handleServerHelloHandshake(payload: HandshakeHelloPayload): void {
    if (!this.handshakeState || this.handshakeState.isReady) {
      return;
    }

    this.handshakeState.pendingServerPublicKey = payload.publicKey;

    if (this.shouldAttemptSessionResumption() && this.sendResumeHandshake()) {
      return;
    }

    this.completeFullHandshake(payload.publicKey);
  }

  private handleResumeAckHandshake(payload: HandshakeResumeAckPayload): void {
    if (!this.handshakeState || this.handshakeState.isReady) {
      return;
    }

    const resumeAttempt = this.handshakeState.resumeAttempt;

    if (!resumeAttempt || resumeAttempt.status !== "pending") {
      return;
    }

    if (!payload.ok) {
      this.sessionTicket = null;
      this.fallbackToFullHandshake();
      return;
    }

    if (payload.sessionId !== resumeAttempt.sessionId || !payload.serverProof) {
      this.sessionTicket = null;
      this.fallbackToFullHandshake();
      return;
    }

    try {
      const receivedServerProof = decodeBase64ToBuffer(
        payload.serverProof,
        "Handshake resume-ack serverProof"
      );

      const expectedServerProof = createResumeServerProof(
        resumeAttempt.resumedKey,
        resumeAttempt.sessionId,
        resumeAttempt.clientNonce
      );

      if (!equalsConstantTime(receivedServerProof, expectedServerProof)) {
        throw new Error("Resume server proof validation failed.");
      }

      this.handshakeState.sharedSecret = resumeAttempt.resumedKey;
      this.handshakeState.encryptionKey = resumeAttempt.resumedKey;
      this.handshakeState.pendingServerPublicKey = null;
      resumeAttempt.status = "accepted";
      this.handshakeState.isReady = true;

      void this.flushPendingPayloadQueue();
      this.notifyReady();
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to verify resume server proof."));
      this.sessionTicket = null;
      this.fallbackToFullHandshake();
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

      if (payload.type === "hello") {
        this.handleServerHelloHandshake(payload);
        return;
      }

      if (payload.type === "resume-ack") {
        this.handleResumeAckHandshake(payload);
        return;
      }

      throw new Error("SecureClient received unexpected resume request handshake payload.");
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
