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
const READY_EVENT = "ready";
const HANDSHAKE_CURVE = "prime256v1";
const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const GCM_IV_LENGTH = 12;
const GCM_AUTH_TAG_LENGTH = 16;
const ENCRYPTION_KEY_LENGTH = 32;
const ENCRYPTED_PACKET_VERSION = 1;
const ENCRYPTED_PACKET_PREFIX_LENGTH = 1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;

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

export interface SecureEnvelope<TData = unknown> {
  event: string;
  data: TData;
}

export interface SecureServerOptions extends WebSocketServerOptions {}

export interface SecureClientOptions {
  protocols?: string | string[];
  wsOptions?: ClientOptions;
  autoConnect?: boolean;
}

export interface SecureServerClient {
  id: string;
  socket: WebSocket;
  request: IncomingMessage;
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
) => void;

export type SecureServerConnectionHandler = (
  client: SecureServerClient
) => void;

export type SecureServerDisconnectHandler = (
  client: SecureServerClient,
  code: number,
  reason: string
) => void;

export type SecureServerReadyHandler = (client: SecureServerClient) => void;

export type SecureClientEventHandler = (data: unknown) => void;

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

function serializeEnvelope(event: string, data: unknown): string {
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
    data: parsed.data
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
    data: parsed.data
  };
}

function decodeCloseReason(reason: Buffer): string {
  return reason.toString("utf8");
}

function isReservedEmitEvent(event: string): boolean {
  return event === INTERNAL_HANDSHAKE_EVENT || event === READY_EVENT;
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

  private readonly roomMembersByName = new Map<string, Set<string>>();

  private readonly roomNamesByClientId = new Map<string, Set<string>>();

  public constructor(options: SecureServerOptions) {
    this.socketServer = new WebSocketServer(options);
    this.bindSocketServerEvents();
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
        this.sendOrQueuePayload(client.socket, envelope);
      }
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to emit server event."));
    }

    return this;
  }

  public emitTo(clientId: string, event: string, data: unknown): boolean {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      const client = this.clientsById.get(clientId);

      if (!client) {
        throw new Error(`Client with id ${clientId} was not found.`);
      }

      this.sendOrQueuePayload(client.socket, { event, data });
      return true;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to emit event to client."));
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
      for (const client of this.clientsById.values()) {
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
      this.roomNamesByClientId.set(clientId, new Set<string>());

      socket.on("message", (rawData: RawData) => {
        this.handleIncomingMessage(client, rawData);
      });

      socket.on("close", (code: number, reason: Buffer) => {
        this.handleDisconnection(client, code, reason);
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
        handler(data, client);
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

  private sendEncryptedEnvelope(socket: WebSocket, envelope: SecureEnvelope): void {
    try {
      if (socket.readyState !== WebSocket.OPEN) {
        return;
      }

      const encryptionKey = this.encryptionKeyBySocket.get(socket);

      if (!encryptionKey) {
        throw new Error("Missing encryption key for connected socket.");
      }

      const encryptedPayload = encryptSerializedEnvelope(
        serializeEnvelope(envelope.event, envelope.data),
        encryptionKey
      );

      socket.send(encryptedPayload);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send encrypted server payload."));
    }
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
      serializeEnvelope(INTERNAL_HANDSHAKE_EVENT, {
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

  private sendOrQueuePayload(socket: WebSocket, envelope: SecureEnvelope): void {
    if (!this.isClientHandshakeReady(socket)) {
      this.queuePayload(socket, envelope);
      return;
    }

    this.sendEncryptedEnvelope(socket, envelope);
  }

  private queuePayload(socket: WebSocket, envelope: SecureEnvelope): void {
    const pendingPayloads = this.pendingPayloadsBySocket.get(socket) ?? [];
    pendingPayloads.push(envelope);
    this.pendingPayloadsBySocket.set(socket, pendingPayloads);
  }

  private flushQueuedPayloads(socket: WebSocket): void {
    const pendingPayloads = this.pendingPayloadsBySocket.get(socket);

    if (!pendingPayloads || pendingPayloads.length === 0) {
      return;
    }

    this.pendingPayloadsBySocket.delete(socket);

    for (const envelope of pendingPayloads) {
      this.sendEncryptedEnvelope(socket, envelope);
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

      this.sendOrQueuePayload(client.socket, envelope);
    }
  }
}

export class SecureClient {
  private socket: WebSocket | null = null;

  private readonly customEventHandlers = new Map<string, Set<SecureClientEventHandler>>();

  private readonly connectHandlers = new Set<SecureClientConnectHandler>();

  private readonly disconnectHandlers = new Set<SecureClientDisconnectHandler>();

  private readonly readyHandlers = new Set<SecureClientReadyHandler>();

  private readonly errorHandlers = new Set<SecureErrorHandler>();

  private handshakeState: ClientHandshakeState | null = null;

  private pendingPayloadQueue: SecureEnvelope[] = [];

  public constructor(
    private readonly url: string,
    private readonly options: SecureClientOptions = {}
  ) {
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

      const socket = this.createSocket();
      this.socket = socket;
      this.handshakeState = this.createClientHandshakeState();
      this.pendingPayloadQueue = [];
      this.bindSocketEvents(socket);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to connect client."));
    }
  }

  public disconnect(
    code: number = DEFAULT_CLOSE_CODE,
    reason: string = DEFAULT_CLOSE_REASON
  ): void {
    try {
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

  public emit(event: string, data: unknown): boolean {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }

      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Client socket is not connected.");
      }

      const envelope: SecureEnvelope = { event, data };

      if (!this.isHandshakeReady()) {
        this.pendingPayloadQueue.push(envelope);
        return true;
      }

      this.sendEncryptedEnvelope(envelope);
      return true;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to emit client event."));
      return false;
    }
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
        handler(data);
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

  private sendEncryptedEnvelope(envelope: SecureEnvelope): void {
    try {
      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Client socket is not connected.");
      }

      const encryptionKey = this.handshakeState?.encryptionKey;

      if (!encryptionKey) {
        throw new Error("Missing encryption key for client payload encryption.");
      }

      const encryptedPayload = encryptSerializedEnvelope(
        serializeEnvelope(envelope.event, envelope.data),
        encryptionKey
      );

      this.socket.send(encryptedPayload);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send encrypted client payload."));
    }
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
        serializeEnvelope(INTERNAL_HANDSHAKE_EVENT, {
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

      this.flushPendingPayloadQueue();
      this.notifyReady();
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to complete client handshake."));
    }
  }

  private isHandshakeReady(): boolean {
    return this.handshakeState?.isReady ?? false;
  }

  private flushPendingPayloadQueue(): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN || !this.isHandshakeReady()) {
      return;
    }

    const pendingPayloads = this.pendingPayloadQueue;
    this.pendingPayloadQueue = [];

    for (const envelope of pendingPayloads) {
      this.sendEncryptedEnvelope(envelope);
    }
  }
}
