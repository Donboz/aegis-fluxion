const DEFAULT_CLOSE_CODE = 1000;
const DEFAULT_CLOSE_REASON = "";
const INTERNAL_HANDSHAKE_EVENT = "__handshake";
const INTERNAL_SESSION_TICKET_EVENT = "__session:ticket";
const INTERNAL_RPC_REQUEST_EVENT = "__rpc:req";
const INTERNAL_RPC_RESPONSE_EVENT = "__rpc:res";
const INTERNAL_STREAM_FRAME_EVENT = "__stream:frame";
const READY_EVENT = "ready";
const HANDSHAKE_PROTOCOL_VERSION = 1;
const HANDSHAKE_CURVE = "P-256";
const ENCRYPTED_PACKET_VERSION = 1;
const GCM_IV_LENGTH = 12;
const GCM_AUTH_TAG_LENGTH = 16;
const STREAM_FRAME_VERSION = 1;
const DEFAULT_STREAM_CHUNK_SIZE_BYTES = 64 * 1024;
const MAX_STREAM_CHUNK_SIZE_BYTES = 1024 * 1024;
const BINARY_PAYLOAD_MARKER = "__afxBinaryPayload";
const BINARY_PAYLOAD_VERSION = 1;
const DEFAULT_RPC_TIMEOUT_MS = 5_000;
const DEFAULT_RECONNECT_INITIAL_DELAY_MS = 250;
const DEFAULT_RECONNECT_MAX_DELAY_MS = 10_000;
const DEFAULT_RECONNECT_FACTOR = 2;
const DEFAULT_RECONNECT_JITTER_RATIO = 0.2;

interface HandshakeHelloPayload {
  type: "hello";
  protocolVersion: typeof HANDSHAKE_PROTOCOL_VERSION;
  publicKey: string;
}

type HandshakePayload = HandshakeHelloPayload;

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

type BinaryPayloadKind = "buffer" | "uint8array" | "blob";

interface EncodedBinaryPayload {
  [BINARY_PAYLOAD_MARKER]: number;
  kind: BinaryPayloadKind;
  base64: string;
  mimeType?: string;
}

interface BrowserClientHandshakeMaterial {
  privateKey: CryptoKey;
  localPublicKey: string;
}

interface BrowserClientHandshakeState {
  materialPromise: Promise<BrowserClientHandshakeMaterial>;
  clientHelloSent: boolean;
  pendingServerPublicKey: string | null;
  isReady: boolean;
  encryptionKey: CryptoKey | null;
  sharedSecret: Uint8Array | null;
}

interface EncryptedPacketParts {
  iv: Uint8Array;
  authTag: Uint8Array;
  ciphertext: Uint8Array;
}

interface IncomingBrowserStreamState {
  info: BrowserIncomingStreamInfo;
  stream: ReadableStream<Uint8Array>;
  controller: ReadableStreamDefaultController<Uint8Array>;
  expectedChunkIndex: number;
  receivedBytes: number;
}

export interface BrowserSecureEnvelope<TData = unknown> {
  event: string;
  data: TData;
}

export type BrowserBinaryPayload = Uint8Array | ArrayBuffer | Blob;

export type BrowserChunkSourceValue =
  | Uint8Array
  | ArrayBuffer
  | Blob
  | string;

export type BrowserChunkedStreamSource =
  | Uint8Array
  | ArrayBuffer
  | Blob
  | ReadableStream<BrowserChunkSourceValue>
  | AsyncIterable<BrowserChunkSourceValue>
  | string;

export interface BrowserChunkedStreamOptions {
  chunkSizeBytes?: number;
  metadata?: Record<string, unknown>;
  totalBytes?: number;
  signal?: AbortSignal;
}

export interface BrowserStreamSendResult {
  streamId: string;
  chunkCount: number;
  totalBytes: number;
}

export interface BrowserIncomingStreamInfo {
  streamId: string;
  event: string;
  metadata?: Record<string, unknown>;
  totalBytes?: number;
  startedAt: number;
}

export interface BrowserSecureAckOptions {
  timeoutMs?: number;
}

export type BrowserSecureAckCallback = (
  error: Error | null,
  response?: unknown
) => void;

export type BrowserClientEventHandler = (
  data: unknown
) => unknown | Promise<unknown>;

export type BrowserClientStreamHandler = (
  stream: ReadableStream<Uint8Array>,
  info: BrowserIncomingStreamInfo
) => void | Promise<void>;

export type BrowserClientConnectHandler = () => void;

export type BrowserClientDisconnectHandler = (
  code: number,
  reason: string
) => void;

export type BrowserClientReadyHandler = () => void;

export type BrowserClientErrorHandler = (error: Error) => void;

export interface BrowserSecureReconnectOptions {
  enabled?: boolean;
  initialDelayMs?: number;
  maxDelayMs?: number;
  factor?: number;
  jitterRatio?: number;
  maxAttempts?: number | null;
}

export interface BrowserSecureClientOptions {
  protocols?: string | string[];
  autoConnect?: boolean;
  reconnect?: boolean | BrowserSecureReconnectOptions;
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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && "then" in value;
}

function isBlobValue(value: unknown): value is Blob {
  return typeof Blob !== "undefined" && value instanceof Blob;
}

function isArrayBufferValue(value: unknown): value is ArrayBuffer {
  return value instanceof ArrayBuffer;
}

function isReadableStreamValue(value: unknown): value is ReadableStream<unknown> {
  return typeof ReadableStream !== "undefined" && value instanceof ReadableStream;
}

function isAsyncIterableValue(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    Symbol.asyncIterator in value
  );
}

function ensureWebCrypto(): Crypto {
  if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
    throw new Error(
      "BrowserSecureClient requires the Web Crypto API (globalThis.crypto.subtle)."
    );
  }

  return globalThis.crypto;
}

function ensureWebSocketClass(): typeof WebSocket {
  if (typeof WebSocket === "undefined") {
    throw new Error("BrowserSecureClient requires global WebSocket support.");
  }

  return WebSocket;
}

function unrefTimer(timeoutHandle: ReturnType<typeof setTimeout>): void {
  (timeoutHandle as unknown as { unref?: () => void }).unref?.();
}

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

function createRandomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("Random byte length must be a positive integer.");
  }

  const bytes = new Uint8Array(length);
  ensureWebCrypto().getRandomValues(bytes);
  return bytes;
}

function createRandomUuid(): string {
  const webCrypto = ensureWebCrypto();

  if (typeof webCrypto.randomUUID === "function") {
    return webCrypto.randomUUID();
  }

  const bytes = createRandomBytes(16);
  const byte6 = bytes[6] ?? 0;
  const byte8 = bytes[8] ?? 0;
  bytes[6] = (byte6 & 0x0f) | 0x40;
  bytes[8] = (byte8 & 0x3f) | 0x80;

  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;

  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, index + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function decodeBase64ToBytes(value: string, fieldName: string): Uint8Array {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty base64 string.`);
  }

  const normalized = value.trim();
  let binary: string;

  try {
    binary = atob(normalized);
  } catch {
    throw new Error(`${fieldName} is not valid base64 content.`);
  }

  const decoded = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    decoded[index] = binary.charCodeAt(index);
  }

  const canonicalInput = normalized.replace(/=+$/u, "");
  const canonicalDecoded = bytesToBase64(decoded).replace(/=+$/u, "");

  if (canonicalInput !== canonicalDecoded) {
    throw new Error(`${fieldName} is not valid base64 content.`);
  }

  return decoded;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const cloned = new Uint8Array(bytes.byteLength);
  cloned.set(bytes);
  return cloned.buffer;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function encodeBinaryPayload(
  kind: BinaryPayloadKind,
  payload: Uint8Array,
  mimeType?: string
): EncodedBinaryPayload {
  const encodedPayload: EncodedBinaryPayload = {
    [BINARY_PAYLOAD_MARKER]: BINARY_PAYLOAD_VERSION,
    kind,
    base64: bytesToBase64(payload)
  };

  if (mimeType !== undefined && mimeType.length > 0) {
    encodedPayload.mimeType = mimeType;
  }

  return encodedPayload;
}

async function encodeEnvelopeData(value: unknown): Promise<unknown> {
  if (value instanceof Uint8Array) {
    return encodeBinaryPayload("uint8array", value);
  }

  if (isArrayBufferValue(value)) {
    return encodeBinaryPayload("uint8array", new Uint8Array(value));
  }

  if (isBlobValue(value)) {
    return encodeBinaryPayload(
      "blob",
      new Uint8Array(await value.arrayBuffer()),
      value.type
    );
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
    const decodedPayload = decodeBase64ToBytes(value.base64, "Binary payload");

    if (value.kind === "blob") {
      if (typeof Blob === "undefined") {
        return decodedPayload;
      }

      return new Blob([toArrayBuffer(decodedPayload)], {
        type: value.mimeType ?? ""
      });
    }

    return decodedPayload;
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
  return JSON.stringify({ event, data: encodedData } satisfies BrowserSecureEnvelope);
}

function serializePlainEnvelope(event: string, data: unknown): string {
  return JSON.stringify({ event, data } satisfies BrowserSecureEnvelope);
}

function parseEnvelopeFromText(decodedPayload: string): BrowserSecureEnvelope {
  const parsed = JSON.parse(decodedPayload) as Partial<BrowserSecureEnvelope>;

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

function parseHandshakePayload(data: unknown): HandshakePayload {
  if (!isPlainObject(data)) {
    throw new Error("Invalid handshake payload format.");
  }

  if (typeof data.type !== "string") {
    if (typeof data.publicKey === "string" && data.publicKey.length > 0) {
      return {
        type: "hello",
        protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
        publicKey: data.publicKey
      };
    }

    throw new Error("Handshake payload must include a valid type.");
  }

  const protocolVersion =
    data.protocolVersion === undefined
      ? HANDSHAKE_PROTOCOL_VERSION
      : data.protocolVersion;

  if (protocolVersion !== HANDSHAKE_PROTOCOL_VERSION) {
    throw new Error(
      `Unsupported handshake protocol version: ${String(protocolVersion)}.`
    );
  }

  if (data.type !== "hello") {
    throw new Error(`Unsupported handshake payload type: ${data.type}.`);
  }

  if (typeof data.publicKey !== "string" || data.publicKey.length === 0) {
    throw new Error("Handshake hello payload must include a non-empty public key.");
  }

  return {
    type: "hello",
    protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
    publicKey: data.publicKey
  };
}

function parseRpcRequestPayload(data: unknown): RpcRequestPayload {
  if (!isPlainObject(data)) {
    throw new Error("Invalid RPC request payload format.");
  }

  if (typeof data.id !== "string" || data.id.trim().length === 0) {
    throw new Error("RPC request payload must include a non-empty id.");
  }

  if (typeof data.event !== "string" || data.event.trim().length === 0) {
    throw new Error("RPC request payload must include a non-empty event.");
  }

  return {
    id: data.id,
    event: data.event,
    data: data.data
  };
}

function parseRpcResponsePayload(data: unknown): RpcResponsePayload {
  if (!isPlainObject(data)) {
    throw new Error("Invalid RPC response payload format.");
  }

  if (typeof data.id !== "string" || data.id.trim().length === 0) {
    throw new Error("RPC response payload must include a non-empty id.");
  }

  if (typeof data.ok !== "boolean") {
    throw new Error("RPC response payload must include a boolean ok field.");
  }

  if (data.error !== undefined && typeof data.error !== "string") {
    throw new Error("RPC response payload error must be a string when provided.");
  }

  const parsedPayload: RpcResponsePayload = {
    id: data.id,
    ok: data.ok,
    data: data.data
  };

  if (data.error !== undefined) {
    parsedPayload.error = data.error;
  }

  return parsedPayload;
}

function normalizeAckArguments(
  callbackOrOptions?: BrowserSecureAckCallback | BrowserSecureAckOptions,
  maybeCallback?: BrowserSecureAckCallback
): {
  expectsAck: boolean;
  callback?: BrowserSecureAckCallback;
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

  if (
    callbackOrOptions !== undefined &&
    (typeof callbackOrOptions !== "object" || callbackOrOptions === null)
  ) {
    throw new Error("ACK options must be an object.");
  }

  if (maybeCallback !== undefined && typeof maybeCallback !== "function") {
    throw new Error("ACK callback must be a function.");
  }

  const timeoutMs = callbackOrOptions?.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("ACK timeoutMs must be a positive number.");
  }

  return {
    ...(maybeCallback ? { callback: maybeCallback } : {}),
    expectsAck: true,
    timeoutMs
  };
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
  source: BrowserChunkedStreamSource,
  hint: number | undefined
): number | undefined {
  if (hint !== undefined) {
    if (!Number.isInteger(hint) || hint < 0) {
      throw new Error("Stream totalBytes must be a non-negative integer.");
    }

    return hint;
  }

  if (source instanceof Uint8Array) {
    return source.byteLength;
  }

  if (isArrayBufferValue(source)) {
    return source.byteLength;
  }

  if (isBlobValue(source)) {
    return source.size;
  }

  if (typeof source === "string") {
    return utf8Encoder.encode(source).byteLength;
  }

  return undefined;
}

async function normalizeChunkSourceValue(value: unknown): Promise<Uint8Array> {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (isArrayBufferValue(value)) {
    return new Uint8Array(value);
  }

  if (isBlobValue(value)) {
    return new Uint8Array(await value.arrayBuffer());
  }

  if (typeof value === "string") {
    return utf8Encoder.encode(value);
  }

  throw new Error("Stream source yielded an unsupported chunk value.");
}

function splitChunkBytes(chunk: Uint8Array, chunkSizeBytes: number): Uint8Array[] {
  if (chunk.byteLength <= chunkSizeBytes) {
    return [chunk];
  }

  const chunkParts: Uint8Array[] = [];

  for (let offset = 0; offset < chunk.byteLength; offset += chunkSizeBytes) {
    chunkParts.push(chunk.subarray(offset, offset + chunkSizeBytes));
  }

  return chunkParts;
}

async function* readableStreamToAsyncIterable(
  stream: ReadableStream<unknown>
): AsyncGenerator<unknown> {
  const reader = stream.getReader();

  try {
    while (true) {
      const { value, done } = await reader.read();

      if (done) {
        return;
      }

      yield value;
    }
  } finally {
    reader.releaseLock();
  }
}

async function* createChunkStreamIterator(
  source: BrowserChunkedStreamSource,
  chunkSizeBytes: number
): AsyncGenerator<Uint8Array> {
  if (source instanceof Uint8Array) {
    yield* splitChunkBytes(source, chunkSizeBytes);
    return;
  }

  if (isArrayBufferValue(source)) {
    yield* splitChunkBytes(new Uint8Array(source), chunkSizeBytes);
    return;
  }

  if (typeof source === "string") {
    yield* splitChunkBytes(utf8Encoder.encode(source), chunkSizeBytes);
    return;
  }

  if (isBlobValue(source)) {
    yield* splitChunkBytes(new Uint8Array(await source.arrayBuffer()), chunkSizeBytes);
    return;
  }

  if (isReadableStreamValue(source)) {
    for await (const chunkValue of readableStreamToAsyncIterable(source)) {
      const normalizedChunk = await normalizeChunkSourceValue(chunkValue);

      if (normalizedChunk.byteLength === 0) {
        continue;
      }

      yield* splitChunkBytes(normalizedChunk, chunkSizeBytes);
    }

    return;
  }

  if (isAsyncIterableValue(source)) {
    for await (const chunkValue of source) {
      const normalizedChunk = await normalizeChunkSourceValue(chunkValue);

      if (normalizedChunk.byteLength === 0) {
        continue;
      }

      yield* splitChunkBytes(normalizedChunk, chunkSizeBytes);
    }

    return;
  }

  throw new Error("Unsupported stream source type.");
}

function parseStreamFramePayload(data: unknown): StreamFramePayload {
  if (!isPlainObject(data)) {
    throw new Error("Invalid stream frame payload format.");
  }

  if (data.version !== STREAM_FRAME_VERSION) {
    throw new Error(`Unsupported stream frame version: ${String(data.version)}.`);
  }

  const streamId = data.streamId;

  if (typeof streamId !== "string" || streamId.trim().length === 0) {
    throw new Error("Stream frame streamId must be a non-empty string.");
  }

  const normalizedStreamId = streamId.trim();

  if (data.type === "start") {
    const event = data.event;

    if (typeof event !== "string" || event.trim().length === 0) {
      throw new Error("Stream start frame event must be a non-empty string.");
    }

    const normalizedEvent = event.trim();
    const totalBytesRaw = data.totalBytes;
    let totalBytes: number | undefined;

    if (totalBytesRaw !== undefined) {
      if (!isNonNegativeInteger(totalBytesRaw)) {
        throw new Error("Stream start frame totalBytes must be a non-negative integer.");
      }

      totalBytes = totalBytesRaw;
    }

    const metadataRaw = data.metadata;

    if (metadataRaw !== undefined && !isPlainObject(metadataRaw)) {
      throw new Error("Stream start frame metadata must be a plain object when provided.");
    }

    const startPayload: StreamFrameStartPayload = {
      version: STREAM_FRAME_VERSION,
      type: "start",
      streamId: normalizedStreamId,
      event: normalizedEvent
    };

    if (metadataRaw !== undefined) {
      startPayload.metadata = metadataRaw;
    }

    if (totalBytes !== undefined) {
      startPayload.totalBytes = totalBytes;
    }

    return startPayload;
  }

  if (data.type === "chunk") {
    const index = data.index;

    if (!isNonNegativeInteger(index)) {
      throw new Error("Stream chunk frame index must be a non-negative integer.");
    }

    const payload = data.payload;

    if (typeof payload !== "string" || payload.length === 0) {
      throw new Error("Stream chunk frame payload must be a non-empty base64 string.");
    }

    const byteLength = data.byteLength;

    if (!isPositiveInteger(byteLength)) {
      throw new Error("Stream chunk frame byteLength must be a positive integer.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "chunk",
      streamId: normalizedStreamId,
      index,
      payload,
      byteLength
    };
  }

  if (data.type === "end") {
    const chunkCount = data.chunkCount;

    if (!isNonNegativeInteger(chunkCount)) {
      throw new Error("Stream end frame chunkCount must be a non-negative integer.");
    }

    const totalBytes = data.totalBytes;

    if (!isNonNegativeInteger(totalBytes)) {
      throw new Error("Stream end frame totalBytes must be a non-negative integer.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "end",
      streamId: normalizedStreamId,
      chunkCount,
      totalBytes
    };
  }

  if (data.type === "abort") {
    const reason = data.reason;

    if (typeof reason !== "string" || reason.trim().length === 0) {
      throw new Error("Stream abort frame reason must be a non-empty string.");
    }

    return {
      version: STREAM_FRAME_VERSION,
      type: "abort",
      streamId: normalizedStreamId,
      reason: reason.trim()
    };
  }

  throw new Error("Unsupported stream frame type.");
}

async function transmitChunkedStreamFrames(
  event: string,
  source: BrowserChunkedStreamSource,
  options: BrowserChunkedStreamOptions | undefined,
  sendFrame: (framePayload: StreamFramePayload) => Promise<void>
): Promise<BrowserStreamSendResult> {
  const chunkSizeBytes = normalizeStreamChunkSize(options?.chunkSizeBytes);
  const totalBytesHint = resolveKnownStreamSourceSize(source, options?.totalBytes);

  if (options?.metadata !== undefined && !isPlainObject(options.metadata)) {
    throw new Error("Stream metadata must be a plain object when provided.");
  }

  if (options?.signal?.aborted) {
    throw new Error("Stream transfer aborted before dispatch.");
  }

  const streamId = createRandomUuid();
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
    for await (const chunkBytes of createChunkStreamIterator(source, chunkSizeBytes)) {
      if (options?.signal?.aborted) {
        throw new Error("Stream transfer aborted by caller signal.");
      }

      if (chunkBytes.byteLength === 0) {
        continue;
      }

      await sendFrame({
        version: STREAM_FRAME_VERSION,
        type: "chunk",
        streamId,
        index: chunkCount,
        payload: bytesToBase64(chunkBytes),
        byteLength: chunkBytes.byteLength
      });

      chunkCount += 1;
      totalBytes += chunkBytes.byteLength;
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

async function createClientHandshakeMaterial(): Promise<BrowserClientHandshakeMaterial> {
  const subtle = ensureWebCrypto().subtle;
  const keyPair = await subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: HANDSHAKE_CURVE
    },
    true,
    ["deriveBits"]
  );

  const exportedPublicKey = await subtle.exportKey("raw", keyPair.publicKey);

  return {
    privateKey: keyPair.privateKey,
    localPublicKey: bytesToBase64(new Uint8Array(exportedPublicKey))
  };
}

async function importServerPublicKey(publicKey: string): Promise<CryptoKey> {
  const subtle = ensureWebCrypto().subtle;
  const decodedPublicKey = decodeBase64ToBytes(publicKey, "Handshake remote publicKey");

  return subtle.importKey(
    "raw",
    toArrayBuffer(decodedPublicKey),
    {
      name: "ECDH",
      namedCurve: HANDSHAKE_CURVE
    },
    false,
    []
  );
}

async function deriveEncryptionKey(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
  const subtle = ensureWebCrypto().subtle;
  const digest = await subtle.digest("SHA-256", sharedSecret);

  return subtle.importKey(
    "raw",
    digest,
    {
      name: "AES-GCM"
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSerializedEnvelope(
  serializedEnvelope: string,
  encryptionKey: CryptoKey
): Promise<Uint8Array> {
  const subtle = ensureWebCrypto().subtle;
  const iv = createRandomBytes(GCM_IV_LENGTH);
  const encrypted = new Uint8Array(
    await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        tagLength: GCM_AUTH_TAG_LENGTH * 8
      },
      encryptionKey,
      toArrayBuffer(utf8Encoder.encode(serializedEnvelope))
    )
  );

  if (encrypted.byteLength <= GCM_AUTH_TAG_LENGTH) {
    throw new Error("Encrypted payload is too short.");
  }

  const ciphertextLength = encrypted.byteLength - GCM_AUTH_TAG_LENGTH;
  const ciphertext = encrypted.subarray(0, ciphertextLength);
  const authTag = encrypted.subarray(ciphertextLength);

  const packet = new Uint8Array(1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH + ciphertext.byteLength);
  packet[0] = ENCRYPTED_PACKET_VERSION;
  packet.set(iv, 1);
  packet.set(authTag, 1 + GCM_IV_LENGTH);
  packet.set(ciphertext, 1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH);

  return packet;
}

function parseEncryptedPacket(packetBytes: Uint8Array): EncryptedPacketParts {
  if (packetBytes.byteLength <= 1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH) {
    throw new Error("Encrypted packet is too short.");
  }

  const version = packetBytes[0];

  if (version !== ENCRYPTED_PACKET_VERSION) {
    throw new Error("Unsupported encrypted packet version.");
  }

  const ivStart = 1;
  const ivEnd = ivStart + GCM_IV_LENGTH;
  const authTagStart = ivEnd;
  const authTagEnd = authTagStart + GCM_AUTH_TAG_LENGTH;

  const iv = packetBytes.subarray(ivStart, ivEnd);
  const authTag = packetBytes.subarray(authTagStart, authTagEnd);
  const ciphertext = packetBytes.subarray(authTagEnd);

  if (ciphertext.byteLength === 0) {
    throw new Error("Encrypted payload is empty.");
  }

  return {
    iv,
    authTag,
    ciphertext
  };
}

async function decryptSerializedEnvelope(
  packetBytes: Uint8Array,
  encryptionKey: CryptoKey
): Promise<string> {
  const subtle = ensureWebCrypto().subtle;
  const encryptedPacket = parseEncryptedPacket(packetBytes);
  const combined = new Uint8Array(
    encryptedPacket.ciphertext.byteLength + encryptedPacket.authTag.byteLength
  );

  combined.set(encryptedPacket.ciphertext, 0);
  combined.set(encryptedPacket.authTag, encryptedPacket.ciphertext.byteLength);

  const decrypted = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(encryptedPacket.iv),
      tagLength: GCM_AUTH_TAG_LENGTH * 8
    },
    encryptionKey,
    toArrayBuffer(combined)
  );

  return utf8Decoder.decode(decrypted);
}

async function messageDataToUint8Array(data: ArrayBuffer | Blob): Promise<Uint8Array> {
  if (isArrayBufferValue(data)) {
    return new Uint8Array(data);
  }

  if (isBlobValue(data)) {
    return new Uint8Array(await data.arrayBuffer());
  }

  throw new Error("Unsupported WebSocket binary message data type.");
}

export class BrowserSecureClient {
  private socket: WebSocket | null = null;

  private readonly reconnectConfig: Required<BrowserSecureReconnectOptions>;

  private reconnectAttemptCount = 0;

  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  private isManualDisconnectRequested = false;

  private readonly customEventHandlers = new Map<string, Set<BrowserClientEventHandler>>();

  private readonly streamEventHandlers = new Map<string, Set<BrowserClientStreamHandler>>();

  private readonly connectHandlers = new Set<BrowserClientConnectHandler>();

  private readonly disconnectHandlers = new Set<BrowserClientDisconnectHandler>();

  private readonly readyHandlers = new Set<BrowserClientReadyHandler>();

  private readonly errorHandlers = new Set<BrowserClientErrorHandler>();

  private handshakeState: BrowserClientHandshakeState | null = null;

  private pendingPayloadQueue: BrowserSecureEnvelope[] = [];

  private readonly pendingRpcRequests = new Map<string, PendingRpcRequest>();

  private readonly incomingStreams = new Map<string, IncomingBrowserStreamState>();

  public constructor(
    private readonly url: string,
    private readonly options: BrowserSecureClientOptions = {}
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

      const WebSocketClass = ensureWebSocketClass();
      this.clearReconnectTimer();
      this.isManualDisconnectRequested = false;
      this.pendingPayloadQueue = [];
      this.handshakeState = this.createClientHandshakeState();

      const socket = this.createSocket(WebSocketClass);
      socket.binaryType = "arraybuffer";
      this.socket = socket;
      this.bindSocketEvents(socket);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to connect browser client."));

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
      this.notifyError(normalizeToError(error, "Failed to disconnect browser client."));
    }
  }

  public on(event: "connect", handler: BrowserClientConnectHandler): this;
  public on(event: "disconnect", handler: BrowserClientDisconnectHandler): this;
  public on(event: "ready", handler: BrowserClientReadyHandler): this;
  public on(event: "error", handler: BrowserClientErrorHandler): this;
  public on(event: string, handler: BrowserClientEventHandler): this;
  public on(event: string, handler: unknown): this {
    try {
      if (event === "connect") {
        this.connectHandlers.add(handler as BrowserClientConnectHandler);
        return this;
      }

      if (event === "disconnect") {
        this.disconnectHandlers.add(handler as BrowserClientDisconnectHandler);
        return this;
      }

      if (event === READY_EVENT) {
        this.readyHandlers.add(handler as BrowserClientReadyHandler);
        return this;
      }

      if (event === "error") {
        this.errorHandlers.add(handler as BrowserClientErrorHandler);
        return this;
      }

      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved for internal use.`);
      }

      const typedHandler = handler as BrowserClientEventHandler;
      const listeners = this.customEventHandlers.get(event) ?? new Set<BrowserClientEventHandler>();
      listeners.add(typedHandler);
      this.customEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register browser client event handler.")
      );
    }

    return this;
  }

  public off(event: "connect", handler: BrowserClientConnectHandler): this;
  public off(event: "disconnect", handler: BrowserClientDisconnectHandler): this;
  public off(event: "ready", handler: BrowserClientReadyHandler): this;
  public off(event: "error", handler: BrowserClientErrorHandler): this;
  public off(event: string, handler: BrowserClientEventHandler): this;
  public off(event: string, handler: unknown): this {
    try {
      if (event === "connect") {
        this.connectHandlers.delete(handler as BrowserClientConnectHandler);
        return this;
      }

      if (event === "disconnect") {
        this.disconnectHandlers.delete(handler as BrowserClientDisconnectHandler);
        return this;
      }

      if (event === READY_EVENT) {
        this.readyHandlers.delete(handler as BrowserClientReadyHandler);
        return this;
      }

      if (event === "error") {
        this.errorHandlers.delete(handler as BrowserClientErrorHandler);
        return this;
      }

      const listeners = this.customEventHandlers.get(event);

      if (!listeners) {
        return this;
      }

      listeners.delete(handler as BrowserClientEventHandler);

      if (listeners.size === 0) {
        this.customEventHandlers.delete(event);
      }
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to remove browser client event handler.")
      );
    }

    return this;
  }

  public onStream(event: string, handler: BrowserClientStreamHandler): this {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be used as a stream event.`);
      }

      const listeners = this.streamEventHandlers.get(event) ?? new Set<BrowserClientStreamHandler>();
      listeners.add(handler);
      this.streamEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register browser stream handler.")
      );
    }

    return this;
  }

  public offStream(event: string, handler: BrowserClientStreamHandler): this {
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
        normalizeToError(error, "Failed to remove browser stream handler.")
      );
    }

    return this;
  }

  public emit(event: string, data: unknown): boolean;
  public emit(event: string, data: unknown, callback: BrowserSecureAckCallback): boolean;
  public emit(event: string, data: unknown, options: BrowserSecureAckOptions): Promise<unknown>;
  public emit(
    event: string,
    data: unknown,
    options: BrowserSecureAckOptions,
    callback: BrowserSecureAckCallback
  ): boolean;
  public emit(
    event: string,
    data: unknown,
    callbackOrOptions?: BrowserSecureAckCallback | BrowserSecureAckOptions,
    maybeCallback?: BrowserSecureAckCallback
  ): boolean | Promise<unknown> {
    const ackArgs = normalizeAckArguments(callbackOrOptions, maybeCallback);

    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Browser client socket is not connected.");
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

      const envelope: BrowserSecureEnvelope = { event, data };

      if (!this.isHandshakeReady()) {
        this.pendingPayloadQueue.push(envelope);
        return true;
      }

      void this.sendEncryptedEnvelope(envelope).catch(() => {
        return undefined;
      });
      return true;
    } catch (error) {
      const normalizedError = normalizeToError(error, "Failed to emit browser client event.");
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
    source: BrowserChunkedStreamSource,
    options?: BrowserChunkedStreamOptions
  ): Promise<BrowserStreamSendResult> {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Browser client socket is not connected.");
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
    reconnectOptions: boolean | BrowserSecureReconnectOptions | undefined
  ): Required<BrowserSecureReconnectOptions> {
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
      throw new Error(
        "Client reconnect maxDelayMs must be greater than or equal to initialDelayMs."
      );
    }

    if (!Number.isFinite(factor) || factor < 1) {
      throw new Error("Client reconnect factor must be greater than or equal to 1.");
    }

    if (!Number.isFinite(jitterRatio) || jitterRatio < 0 || jitterRatio > 1) {
      throw new Error("Client reconnect jitterRatio must be between 0 and 1.");
    }

    if (maxAttempts !== null && (!Number.isInteger(maxAttempts) || maxAttempts < 0)) {
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

    unrefTimer(this.reconnectTimer);
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

  private createSocket(WebSocketClass: typeof WebSocket): WebSocket {
    if (this.options.protocols !== undefined) {
      return new WebSocketClass(this.url, this.options.protocols);
    }

    return new WebSocketClass(this.url);
  }

  private createClientHandshakeState(): BrowserClientHandshakeState {
    return {
      materialPromise: createClientHandshakeMaterial(),
      clientHelloSent: false,
      pendingServerPublicKey: null,
      isReady: false,
      encryptionKey: null,
      sharedSecret: null
    };
  }

  private bindSocketEvents(socket: WebSocket): void {
    socket.addEventListener("open", () => {
      this.clearReconnectTimer();
      this.reconnectAttemptCount = 0;
      this.notifyConnect();
      void this.sendInternalHandshake();
    });

    socket.addEventListener("message", (event: MessageEvent<string | ArrayBuffer | Blob>) => {
      void this.handleIncomingMessage(event.data);
    });

    socket.addEventListener("close", (event: CloseEvent) => {
      this.handleDisconnect(event.code, event.reason);
    });

    socket.addEventListener("error", () => {
      this.notifyError(new Error("Browser client socket encountered an error."));
    });
  }

  private async sendInternalHandshake(): Promise<void> {
    try {
      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        return;
      }

      if (!this.handshakeState) {
        throw new Error("Missing browser client handshake state.");
      }

      if (this.handshakeState.clientHelloSent) {
        return;
      }

      const handshakeMaterial = await this.handshakeState.materialPromise;

      this.socket.send(
        serializePlainEnvelope(INTERNAL_HANDSHAKE_EVENT, {
          type: "hello",
          protocolVersion: HANDSHAKE_PROTOCOL_VERSION,
          publicKey: handshakeMaterial.localPublicKey
        } satisfies HandshakeHelloPayload)
      );

      this.handshakeState.clientHelloSent = true;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send browser client handshake payload."));
    }
  }

  private async completeFullHandshake(serverPublicKey: string): Promise<void> {
    if (!this.handshakeState || this.handshakeState.isReady) {
      return;
    }

    const subtle = ensureWebCrypto().subtle;
    const remotePublicKey = await importServerPublicKey(serverPublicKey);
    const handshakeMaterial = await this.handshakeState.materialPromise;

    const sharedSecret = await subtle.deriveBits(
      {
        name: "ECDH",
        public: remotePublicKey
      },
      handshakeMaterial.privateKey,
      256
    );

    this.handshakeState.sharedSecret = new Uint8Array(sharedSecret);
    this.handshakeState.encryptionKey = await deriveEncryptionKey(sharedSecret);
    this.handshakeState.pendingServerPublicKey = null;
    this.handshakeState.isReady = true;

    await this.flushPendingPayloadQueue();
    this.notifyReady();
  }

  private async handleInternalHandshake(data: unknown): Promise<void> {
    try {
      const payload = parseHandshakePayload(data);

      if (!this.handshakeState || this.handshakeState.isReady) {
        return;
      }

      this.handshakeState.pendingServerPublicKey = payload.publicKey;
      await this.completeFullHandshake(payload.publicKey);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to complete browser client handshake."));
    }
  }

  private async handleIncomingMessage(data: string | ArrayBuffer | Blob): Promise<void> {
    try {
      if (typeof data === "string") {
        const envelope = parseEnvelopeFromText(data);

        if (envelope.event === INTERNAL_HANDSHAKE_EVENT) {
          await this.handleInternalHandshake(envelope.data);
          return;
        }

        this.notifyError(new Error(`Plaintext event "${envelope.event}" was rejected on client.`));
        return;
      }

      const packetBytes = await messageDataToUint8Array(data);

      if (!this.isHandshakeReady()) {
        this.notifyError(
          new Error("Encrypted payload was received before handshake completion.")
        );
        return;
      }

      const encryptionKey = this.handshakeState?.encryptionKey;

      if (!encryptionKey) {
        this.notifyError(new Error("Missing encryption key for browser payload decryption."));
        return;
      }

      let decryptedPayload: string;

      try {
        decryptedPayload = await decryptSerializedEnvelope(packetBytes, encryptionKey);
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
        await this.handleRpcRequest(decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_STREAM_FRAME_EVENT) {
        this.handleIncomingStreamFrame(decryptedEnvelope.data);
        return;
      }

      if (decryptedEnvelope.event === INTERNAL_SESSION_TICKET_EVENT) {
        // Browser SDK intentionally ignores session ticket internals in this lightweight implementation.
        return;
      }

      this.dispatchCustomEvent(decryptedEnvelope.event, decryptedEnvelope.data);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to process incoming browser client message."));
    }
  }

  private handleDisconnect(code: number, reason: string): void {
    try {
      this.socket = null;
      this.handshakeState = null;
      this.pendingPayloadQueue = [];
      this.cleanupIncomingStreams("Browser client disconnected before stream transfer completed.");
      this.rejectPendingRpcRequests(
        new Error("Browser client disconnected before ACK response was received.")
      );

      for (const handler of this.disconnectHandlers) {
        try {
          handler(code, reason);
        } catch (handlerError) {
          this.notifyError(
            normalizeToError(handlerError, "Browser client disconnect handler failed.")
          );
        }
      }

      if (!this.isManualDisconnectRequested) {
        this.scheduleReconnect();
      }

      this.isManualDisconnectRequested = false;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to handle browser client disconnect."));
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
              normalizeToError(error, `Browser client handler failed for event ${event}.`)
            );
          });
        }
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Browser client handler failed for event ${event}.`)
        );
      }
    }
  }

  private notifyConnect(): void {
    for (const handler of this.connectHandlers) {
      try {
        handler();
      } catch (error) {
        this.notifyError(normalizeToError(error, "Browser client connect handler failed."));
      }
    }
  }

  private notifyReady(): void {
    for (const handler of this.readyHandlers) {
      try {
        handler();
      } catch (error) {
        this.notifyError(normalizeToError(error, "Browser client ready handler failed."));
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

  private isHandshakeReady(): boolean {
    return this.handshakeState?.isReady ?? false;
  }

  private async sendEncryptedEnvelope(envelope: BrowserSecureEnvelope): Promise<void> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      const socketStateError = new Error("Browser client socket is not connected.");
      this.notifyError(socketStateError);
      throw socketStateError;
    }

    const encryptionKey = this.handshakeState?.encryptionKey;

    if (!encryptionKey) {
      const missingKeyError = new Error("Missing encryption key for browser payload encryption.");
      this.notifyError(missingKeyError);
      throw missingKeyError;
    }

    try {
      const serializedEnvelope = await serializeEnvelope(envelope.event, envelope.data);
      const encryptedPayload = await encryptSerializedEnvelope(serializedEnvelope, encryptionKey);
      this.socket.send(encryptedPayload);
    } catch (error) {
      const normalizedError = normalizeToError(error, "Failed to send encrypted browser payload.");
      this.notifyError(normalizedError);
      throw normalizedError;
    }
  }

  private async flushPendingPayloadQueue(): Promise<void> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN || !this.isHandshakeReady()) {
      return;
    }

    const queuedPayloads = this.pendingPayloadQueue;
    this.pendingPayloadQueue = [];

    for (const envelope of queuedPayloads) {
      await this.sendEncryptedEnvelope(envelope);
    }
  }

  private sendRpcRequest(
    event: string,
    data: unknown,
    timeoutMs: number
  ): Promise<unknown> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("Browser client socket is not connected for ACK request.");
    }

    const requestId = createRandomUuid();

    return new Promise<unknown>((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        this.pendingRpcRequests.delete(requestId);
        reject(new Error(`ACK response timed out after ${timeoutMs}ms for event "${event}".`));
      }, timeoutMs);

      unrefTimer(timeoutHandle);

      this.pendingRpcRequests.set(requestId, {
        resolve,
        reject,
        timeoutHandle
      });

      const rpcEnvelope: BrowserSecureEnvelope<RpcRequestPayload> = {
        event: INTERNAL_RPC_REQUEST_EVENT,
        data: {
          id: requestId,
          event,
          data
        }
      };

      if (!this.isHandshakeReady()) {
        this.pendingPayloadQueue.push(rpcEnvelope);
        return;
      }

      void this.sendEncryptedEnvelope(rpcEnvelope).catch((error) => {
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
      this.notifyError(normalizeToError(error, "Failed to process browser ACK response."));
    }
  }

  private async handleRpcRequest(data: unknown): Promise<void> {
    let rpcRequestPayload: RpcRequestPayload;

    try {
      rpcRequestPayload = parseRpcRequestPayload(data);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Invalid browser ACK request payload."));
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
      const normalizedError = normalizeToError(error, "Browser ACK request handler failed.");

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

    const firstHandler = handlers.values().next().value as BrowserClientEventHandler;
    return Promise.resolve(firstHandler(data));
  }

  private rejectPendingRpcRequests(error: Error): void {
    for (const pendingRequest of this.pendingRpcRequests.values()) {
      clearTimeout(pendingRequest.timeoutHandle);
      pendingRequest.reject(error);
    }

    this.pendingRpcRequests.clear();
  }

  private cleanupIncomingStreams(reason: string): void {
    for (const streamState of this.incomingStreams.values()) {
      try {
        streamState.controller.error(new Error(reason));
      } catch {
        // Ignore stream close race.
      }
    }

    this.incomingStreams.clear();
  }

  private abortIncomingClientStream(streamId: string, reason: string): void {
    const streamState = this.incomingStreams.get(streamId);

    if (!streamState) {
      return;
    }

    try {
      streamState.controller.error(new Error(reason));
    } catch {
      // Ignore stream close race.
    }

    this.incomingStreams.delete(streamId);
  }

  private dispatchClientStreamEvent(
    event: string,
    stream: ReadableStream<Uint8Array>,
    info: BrowserIncomingStreamInfo
  ): void {
    const handlers = this.streamEventHandlers.get(event);

    if (!handlers || handlers.size === 0) {
      try {
        stream.cancel(`No stream handler registered for ${event}.`);
      } catch {
        // Ignore stream cancel race.
      }

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
              normalizeToError(error, `Browser stream handler failed for event ${event}.`)
            );
          });
        }
      } catch (error) {
        this.notifyError(
          normalizeToError(error, `Browser stream handler failed for event ${event}.`)
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

    let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;

    const stream = new ReadableStream<Uint8Array>({
      start: (controller) => {
        controllerRef = controller;
      },
      cancel: () => {
        this.incomingStreams.delete(framePayload.streamId);
      }
    });

    if (controllerRef === null) {
      throw new Error(`Failed to initialize stream controller for ${framePayload.streamId}.`);
    }

    const streamInfo: BrowserIncomingStreamInfo = {
      streamId: framePayload.streamId,
      event: framePayload.event,
      startedAt: Date.now(),
      ...(framePayload.metadata !== undefined ? { metadata: framePayload.metadata } : {}),
      ...(framePayload.totalBytes !== undefined ? { totalBytes: framePayload.totalBytes } : {})
    };

    this.incomingStreams.set(framePayload.streamId, {
      info: streamInfo,
      stream,
      controller: controllerRef,
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

    const chunkBytes = decodeBase64ToBytes(
      framePayload.payload,
      `Stream chunk payload (${framePayload.streamId})`
    );

    if (chunkBytes.byteLength !== framePayload.byteLength) {
      throw new Error(
        `Stream ${framePayload.streamId} byteLength mismatch. Expected ${framePayload.byteLength}, received ${chunkBytes.byteLength}.`
      );
    }

    streamState.expectedChunkIndex += 1;
    streamState.receivedBytes += chunkBytes.byteLength;
    streamState.controller.enqueue(chunkBytes);
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

    streamState.controller.close();
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
        "Failed to process incoming stream frame on browser client."
      );

      if (framePayload) {
        this.abortIncomingClientStream(framePayload.streamId, normalizedError.message);
      }

      this.notifyError(normalizedError);
    }
  }
}
