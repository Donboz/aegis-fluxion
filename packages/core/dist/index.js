import { randomUUID, createDecipheriv, randomBytes, createCipheriv, createECDH, createHash } from 'crypto';
import WebSocket, { WebSocketServer } from 'ws';

// src/index.ts
var DEFAULT_CLOSE_CODE = 1e3;
var DEFAULT_CLOSE_REASON = "";
var INTERNAL_HANDSHAKE_EVENT = "__handshake";
var READY_EVENT = "ready";
var HANDSHAKE_CURVE = "prime256v1";
var ENCRYPTION_ALGORITHM = "aes-256-gcm";
var GCM_IV_LENGTH = 12;
var GCM_AUTH_TAG_LENGTH = 16;
var ENCRYPTION_KEY_LENGTH = 32;
var ENCRYPTED_PACKET_VERSION = 1;
var ENCRYPTED_PACKET_PREFIX_LENGTH = 1 + GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH;
var DEFAULT_HEARTBEAT_INTERVAL_MS = 15e3;
var DEFAULT_HEARTBEAT_TIMEOUT_MS = 15e3;
var DEFAULT_RECONNECT_INITIAL_DELAY_MS = 250;
var DEFAULT_RECONNECT_MAX_DELAY_MS = 1e4;
var DEFAULT_RECONNECT_FACTOR = 2;
var DEFAULT_RECONNECT_JITTER_RATIO = 0.2;
function normalizeToError(error, fallbackMessage) {
  if (error instanceof Error) {
    return error;
  }
  if (typeof error === "string" && error.trim().length > 0) {
    return new Error(error);
  }
  return new Error(fallbackMessage);
}
function decodeRawData(rawData) {
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
function rawDataToBuffer(rawData) {
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
function serializeEnvelope(event, data) {
  const envelope = { event, data };
  return JSON.stringify(envelope);
}
function parseEnvelope(rawData) {
  const decoded = decodeRawData(rawData);
  const parsed = JSON.parse(decoded);
  if (typeof parsed !== "object" || parsed === null || typeof parsed.event !== "string") {
    throw new Error("Invalid message format. Expected { event: string, data: unknown }.");
  }
  return {
    event: parsed.event,
    data: parsed.data
  };
}
function parseEnvelopeFromText(decodedPayload) {
  const parsed = JSON.parse(decodedPayload);
  if (typeof parsed !== "object" || parsed === null || typeof parsed.event !== "string") {
    throw new Error("Invalid message format. Expected { event: string, data: unknown }.");
  }
  return {
    event: parsed.event,
    data: parsed.data
  };
}
function decodeCloseReason(reason) {
  return reason.toString("utf8");
}
function isReservedEmitEvent(event) {
  return event === INTERNAL_HANDSHAKE_EVENT || event === READY_EVENT;
}
function createEphemeralHandshakeState() {
  const ecdh = createECDH(HANDSHAKE_CURVE);
  ecdh.generateKeys();
  return {
    ecdh,
    localPublicKey: ecdh.getPublicKey("base64")
  };
}
function parseHandshakePayload(data) {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid handshake payload format.");
  }
  const payload = data;
  if (typeof payload.publicKey !== "string" || payload.publicKey.length === 0) {
    throw new Error("Handshake payload must include a non-empty public key.");
  }
  return {
    publicKey: payload.publicKey
  };
}
function deriveEncryptionKey(sharedSecret) {
  const derivedKey = createHash("sha256").update(sharedSecret).digest();
  if (derivedKey.length !== ENCRYPTION_KEY_LENGTH) {
    throw new Error("Failed to derive a valid AES-256 key.");
  }
  return derivedKey;
}
function encryptSerializedEnvelope(serializedEnvelope, encryptionKey) {
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
function parseEncryptedPacket(rawData) {
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
function decryptSerializedEnvelope(rawData, encryptionKey) {
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
var SecureServer = class {
  socketServer;
  heartbeatConfig;
  heartbeatIntervalHandle = null;
  clientsById = /* @__PURE__ */ new Map();
  clientIdBySocket = /* @__PURE__ */ new Map();
  customEventHandlers = /* @__PURE__ */ new Map();
  connectionHandlers = /* @__PURE__ */ new Set();
  disconnectHandlers = /* @__PURE__ */ new Set();
  readyHandlers = /* @__PURE__ */ new Set();
  errorHandlers = /* @__PURE__ */ new Set();
  handshakeStateBySocket = /* @__PURE__ */ new WeakMap();
  sharedSecretBySocket = /* @__PURE__ */ new WeakMap();
  encryptionKeyBySocket = /* @__PURE__ */ new WeakMap();
  pendingPayloadsBySocket = /* @__PURE__ */ new WeakMap();
  heartbeatStateBySocket = /* @__PURE__ */ new WeakMap();
  roomMembersByName = /* @__PURE__ */ new Map();
  roomNamesByClientId = /* @__PURE__ */ new Map();
  constructor(options) {
    const { heartbeat, ...socketServerOptions } = options;
    this.heartbeatConfig = this.resolveHeartbeatConfig(heartbeat);
    this.socketServer = new WebSocketServer(socketServerOptions);
    this.bindSocketServerEvents();
    this.startHeartbeatLoop();
  }
  get clientCount() {
    return this.clientsById.size;
  }
  get clients() {
    return this.clientsById;
  }
  on(event, handler) {
    try {
      if (event === "connection") {
        this.connectionHandlers.add(handler);
        return this;
      }
      if (event === "disconnect") {
        this.disconnectHandlers.add(handler);
        return this;
      }
      if (event === READY_EVENT) {
        this.readyHandlers.add(handler);
        return this;
      }
      if (event === "error") {
        this.errorHandlers.add(handler);
        return this;
      }
      if (event === INTERNAL_HANDSHAKE_EVENT) {
        throw new Error(`The event "${INTERNAL_HANDSHAKE_EVENT}" is reserved for internal use.`);
      }
      const typedHandler = handler;
      const listeners = this.customEventHandlers.get(event) ?? /* @__PURE__ */ new Set();
      listeners.add(typedHandler);
      this.customEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register server event handler.")
      );
    }
    return this;
  }
  off(event, handler) {
    try {
      if (event === "connection") {
        this.connectionHandlers.delete(handler);
        return this;
      }
      if (event === "disconnect") {
        this.disconnectHandlers.delete(handler);
        return this;
      }
      if (event === READY_EVENT) {
        this.readyHandlers.delete(handler);
        return this;
      }
      if (event === "error") {
        this.errorHandlers.delete(handler);
        return this;
      }
      if (event === INTERNAL_HANDSHAKE_EVENT) {
        return this;
      }
      const listeners = this.customEventHandlers.get(event);
      if (!listeners) {
        return this;
      }
      listeners.delete(handler);
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
  emit(event, data) {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }
      const envelope = { event, data };
      for (const client of this.clientsById.values()) {
        this.sendOrQueuePayload(client.socket, envelope);
      }
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to emit server event."));
    }
    return this;
  }
  emitTo(clientId, event, data) {
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
  to(room) {
    const normalizedRoom = this.normalizeRoomName(room);
    return {
      emit: (event, data) => {
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
  close(code = DEFAULT_CLOSE_CODE, reason = DEFAULT_CLOSE_REASON) {
    try {
      this.stopHeartbeatLoop();
      for (const client of this.clientsById.values()) {
        if (client.socket.readyState === WebSocket.OPEN || client.socket.readyState === WebSocket.CONNECTING) {
          client.socket.close(code, reason);
        }
      }
      this.socketServer.close();
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to close server."));
    }
  }
  resolveHeartbeatConfig(heartbeatOptions) {
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
  startHeartbeatLoop() {
    if (!this.heartbeatConfig.enabled || this.heartbeatIntervalHandle) {
      return;
    }
    this.heartbeatIntervalHandle = setInterval(() => {
      this.performHeartbeatSweep();
    }, this.heartbeatConfig.intervalMs);
    this.heartbeatIntervalHandle.unref?.();
  }
  stopHeartbeatLoop() {
    if (!this.heartbeatIntervalHandle) {
      return;
    }
    clearInterval(this.heartbeatIntervalHandle);
    this.heartbeatIntervalHandle = null;
  }
  performHeartbeatSweep() {
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
      if (heartbeatState.awaitingPong && now - heartbeatState.lastPingAt >= this.heartbeatConfig.timeoutMs) {
        this.sharedSecretBySocket.delete(socket);
        this.encryptionKeyBySocket.delete(socket);
        this.pendingPayloadsBySocket.delete(socket);
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
  handleHeartbeatPong(socket) {
    const heartbeatState = this.heartbeatStateBySocket.get(socket);
    if (!heartbeatState) {
      return;
    }
    heartbeatState.awaitingPong = false;
    heartbeatState.lastPingAt = 0;
    this.heartbeatStateBySocket.set(socket, heartbeatState);
  }
  bindSocketServerEvents() {
    this.socketServer.on("connection", (socket, request) => {
      this.handleConnection(socket, request);
    });
    this.socketServer.on("error", (error) => {
      this.notifyError(normalizeToError(error, "WebSocket server encountered an error."));
    });
  }
  handleConnection(socket, request) {
    try {
      const clientId = randomUUID();
      const handshakeState = this.createServerHandshakeState();
      const client = this.createSecureServerClient(clientId, socket, request);
      this.clientsById.set(clientId, client);
      this.clientIdBySocket.set(socket, clientId);
      this.handshakeStateBySocket.set(socket, handshakeState);
      this.pendingPayloadsBySocket.set(socket, []);
      this.heartbeatStateBySocket.set(socket, {
        awaitingPong: false,
        lastPingAt: 0
      });
      this.roomNamesByClientId.set(clientId, /* @__PURE__ */ new Set());
      socket.on("message", (rawData) => {
        this.handleIncomingMessage(client, rawData);
      });
      socket.on("close", (code, reason) => {
        this.handleDisconnection(client, code, reason);
      });
      socket.on("pong", () => {
        this.handleHeartbeatPong(client.socket);
      });
      socket.on("error", (error) => {
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
  handleIncomingMessage(client, rawData) {
    try {
      let envelope = null;
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
      let decryptedPayload;
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
  handleDisconnection(client, code, reason) {
    try {
      client.leaveAll();
      this.clientsById.delete(client.id);
      this.clientIdBySocket.delete(client.socket);
      this.handshakeStateBySocket.delete(client.socket);
      this.sharedSecretBySocket.delete(client.socket);
      this.encryptionKeyBySocket.delete(client.socket);
      this.pendingPayloadsBySocket.delete(client.socket);
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
  dispatchCustomEvent(event, data, client) {
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
  sendRaw(socket, payload) {
    try {
      if (socket.readyState !== WebSocket.OPEN) {
        return;
      }
      socket.send(payload);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to send server payload."));
    }
  }
  sendEncryptedEnvelope(socket, envelope) {
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
  notifyConnection(client) {
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
  notifyReady(client) {
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
  notifyError(error) {
    if (this.errorHandlers.size === 0) {
      return;
    }
    for (const handler of this.errorHandlers) {
      try {
        handler(error);
      } catch {
      }
    }
  }
  createServerHandshakeState() {
    const { ecdh, localPublicKey } = createEphemeralHandshakeState();
    return {
      ecdh,
      localPublicKey,
      isReady: false
    };
  }
  sendInternalHandshake(socket, localPublicKey) {
    this.sendRaw(
      socket,
      serializeEnvelope(INTERNAL_HANDSHAKE_EVENT, {
        publicKey: localPublicKey
      })
    );
  }
  handleInternalHandshake(client, data) {
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
  isClientHandshakeReady(socket) {
    return this.handshakeStateBySocket.get(socket)?.isReady ?? false;
  }
  sendOrQueuePayload(socket, envelope) {
    if (!this.isClientHandshakeReady(socket)) {
      this.queuePayload(socket, envelope);
      return;
    }
    this.sendEncryptedEnvelope(socket, envelope);
  }
  queuePayload(socket, envelope) {
    const pendingPayloads = this.pendingPayloadsBySocket.get(socket) ?? [];
    pendingPayloads.push(envelope);
    this.pendingPayloadsBySocket.set(socket, pendingPayloads);
  }
  flushQueuedPayloads(socket) {
    const pendingPayloads = this.pendingPayloadsBySocket.get(socket);
    if (!pendingPayloads || pendingPayloads.length === 0) {
      return;
    }
    this.pendingPayloadsBySocket.delete(socket);
    for (const envelope of pendingPayloads) {
      this.sendEncryptedEnvelope(socket, envelope);
    }
  }
  createSecureServerClient(clientId, socket, request) {
    return {
      id: clientId,
      socket,
      request,
      join: (room) => this.joinClientToRoom(clientId, room),
      leave: (room) => this.leaveClientFromRoom(clientId, room),
      leaveAll: () => this.leaveClientFromAllRooms(clientId)
    };
  }
  normalizeRoomName(room) {
    if (typeof room !== "string") {
      throw new Error("Room name must be a string.");
    }
    const normalizedRoom = room.trim();
    if (normalizedRoom.length === 0) {
      throw new Error("Room name cannot be empty.");
    }
    return normalizedRoom;
  }
  joinClientToRoom(clientId, room) {
    const normalizedRoom = this.normalizeRoomName(room);
    if (!this.clientsById.has(clientId)) {
      return false;
    }
    const clientRooms = this.roomNamesByClientId.get(clientId) ?? /* @__PURE__ */ new Set();
    if (clientRooms.has(normalizedRoom)) {
      this.roomNamesByClientId.set(clientId, clientRooms);
      return false;
    }
    clientRooms.add(normalizedRoom);
    this.roomNamesByClientId.set(clientId, clientRooms);
    const roomMembers = this.roomMembersByName.get(normalizedRoom) ?? /* @__PURE__ */ new Set();
    roomMembers.add(clientId);
    this.roomMembersByName.set(normalizedRoom, roomMembers);
    return true;
  }
  leaveClientFromRoom(clientId, room) {
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
  leaveClientFromAllRooms(clientId) {
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
  emitToRoom(room, event, data) {
    if (isReservedEmitEvent(event)) {
      throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
    }
    const roomMembers = this.roomMembersByName.get(room);
    if (!roomMembers || roomMembers.size === 0) {
      return;
    }
    const envelope = { event, data };
    for (const clientId of roomMembers) {
      const client = this.clientsById.get(clientId);
      if (!client) {
        continue;
      }
      this.sendOrQueuePayload(client.socket, envelope);
    }
  }
};
var SecureClient = class {
  constructor(url, options = {}) {
    this.url = url;
    this.options = options;
    this.reconnectConfig = this.resolveReconnectConfig(this.options.reconnect);
    if (this.options.autoConnect ?? true) {
      this.connect();
    }
  }
  url;
  options;
  socket = null;
  reconnectConfig;
  reconnectAttemptCount = 0;
  reconnectTimer = null;
  isManualDisconnectRequested = false;
  customEventHandlers = /* @__PURE__ */ new Map();
  connectHandlers = /* @__PURE__ */ new Set();
  disconnectHandlers = /* @__PURE__ */ new Set();
  readyHandlers = /* @__PURE__ */ new Set();
  errorHandlers = /* @__PURE__ */ new Set();
  handshakeState = null;
  pendingPayloadQueue = [];
  get readyState() {
    return this.socket?.readyState ?? null;
  }
  isConnected() {
    return this.socket?.readyState === WebSocket.OPEN;
  }
  connect() {
    try {
      if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
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
  disconnect(code = DEFAULT_CLOSE_CODE, reason = DEFAULT_CLOSE_REASON) {
    try {
      this.isManualDisconnectRequested = true;
      this.clearReconnectTimer();
      if (!this.socket) {
        return;
      }
      if (this.socket.readyState === WebSocket.CLOSING || this.socket.readyState === WebSocket.CLOSED) {
        return;
      }
      this.socket.close(code, reason);
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to disconnect client."));
    }
  }
  on(event, handler) {
    try {
      if (event === "connect") {
        this.connectHandlers.add(handler);
        return this;
      }
      if (event === "disconnect") {
        this.disconnectHandlers.add(handler);
        return this;
      }
      if (event === READY_EVENT) {
        this.readyHandlers.add(handler);
        return this;
      }
      if (event === "error") {
        this.errorHandlers.add(handler);
        return this;
      }
      if (event === INTERNAL_HANDSHAKE_EVENT) {
        throw new Error(`The event "${INTERNAL_HANDSHAKE_EVENT}" is reserved for internal use.`);
      }
      const typedHandler = handler;
      const listeners = this.customEventHandlers.get(event) ?? /* @__PURE__ */ new Set();
      listeners.add(typedHandler);
      this.customEventHandlers.set(event, listeners);
    } catch (error) {
      this.notifyError(
        normalizeToError(error, "Failed to register client event handler.")
      );
    }
    return this;
  }
  off(event, handler) {
    try {
      if (event === "connect") {
        this.connectHandlers.delete(handler);
        return this;
      }
      if (event === "disconnect") {
        this.disconnectHandlers.delete(handler);
        return this;
      }
      if (event === READY_EVENT) {
        this.readyHandlers.delete(handler);
        return this;
      }
      if (event === "error") {
        this.errorHandlers.delete(handler);
        return this;
      }
      if (event === INTERNAL_HANDSHAKE_EVENT) {
        return this;
      }
      const listeners = this.customEventHandlers.get(event);
      if (!listeners) {
        return this;
      }
      listeners.delete(handler);
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
  emit(event, data) {
    try {
      if (isReservedEmitEvent(event)) {
        throw new Error(`The event "${event}" is reserved and cannot be emitted manually.`);
      }
      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error("Client socket is not connected.");
      }
      const envelope = { event, data };
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
  resolveReconnectConfig(reconnectOptions) {
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
  scheduleReconnect() {
    if (!this.reconnectConfig.enabled || this.reconnectTimer) {
      return;
    }
    if (this.reconnectConfig.maxAttempts !== null && this.reconnectAttemptCount >= this.reconnectConfig.maxAttempts) {
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
  computeReconnectDelay(attemptNumber) {
    const exponentialDelay = Math.min(
      this.reconnectConfig.maxDelayMs,
      this.reconnectConfig.initialDelayMs * Math.pow(this.reconnectConfig.factor, Math.max(0, attemptNumber - 1))
    );
    if (this.reconnectConfig.jitterRatio === 0 || exponentialDelay === 0) {
      return Math.round(exponentialDelay);
    }
    const jitterDelta = exponentialDelay * this.reconnectConfig.jitterRatio;
    const jitterOffset = (Math.random() * 2 - 1) * jitterDelta;
    return Math.max(0, Math.round(exponentialDelay + jitterOffset));
  }
  clearReconnectTimer() {
    if (!this.reconnectTimer) {
      return;
    }
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }
  createSocket() {
    if (this.options.protocols !== void 0) {
      return new WebSocket(this.url, this.options.protocols, this.options.wsOptions);
    }
    if (this.options.wsOptions !== void 0) {
      return new WebSocket(this.url, this.options.wsOptions);
    }
    return new WebSocket(this.url);
  }
  bindSocketEvents(socket) {
    socket.on("open", () => {
      this.clearReconnectTimer();
      this.reconnectAttemptCount = 0;
      this.sendInternalHandshake();
      this.notifyConnect();
    });
    socket.on("message", (rawData) => {
      this.handleIncomingMessage(rawData);
    });
    socket.on("close", (code, reason) => {
      this.handleDisconnect(code, reason);
    });
    socket.on("error", (error) => {
      this.notifyError(normalizeToError(error, "Client socket encountered an error."));
    });
  }
  handleIncomingMessage(rawData) {
    try {
      let envelope = null;
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
      let decryptedPayload;
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
  handleDisconnect(code, reason) {
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
      if (!this.isManualDisconnectRequested) {
        this.scheduleReconnect();
      }
      this.isManualDisconnectRequested = false;
    } catch (error) {
      this.notifyError(normalizeToError(error, "Failed to handle client disconnect."));
    }
  }
  dispatchCustomEvent(event, data) {
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
  notifyConnect() {
    for (const handler of this.connectHandlers) {
      try {
        handler();
      } catch (error) {
        this.notifyError(normalizeToError(error, "Client connect handler failed."));
      }
    }
  }
  notifyReady() {
    for (const handler of this.readyHandlers) {
      try {
        handler();
      } catch (error) {
        this.notifyError(normalizeToError(error, "Client ready handler failed."));
      }
    }
  }
  notifyError(error) {
    if (this.errorHandlers.size === 0) {
      return;
    }
    for (const handler of this.errorHandlers) {
      try {
        handler(error);
      } catch {
      }
    }
  }
  sendEncryptedEnvelope(envelope) {
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
  createClientHandshakeState() {
    const { ecdh, localPublicKey } = createEphemeralHandshakeState();
    return {
      ecdh,
      localPublicKey,
      isReady: false,
      sharedSecret: null,
      encryptionKey: null
    };
  }
  sendInternalHandshake() {
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
  handleInternalHandshake(data) {
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
  isHandshakeReady() {
    return this.handshakeState?.isReady ?? false;
  }
  flushPendingPayloadQueue() {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN || !this.isHandshakeReady()) {
      return;
    }
    const pendingPayloads = this.pendingPayloadQueue;
    this.pendingPayloadQueue = [];
    for (const envelope of pendingPayloads) {
      this.sendEncryptedEnvelope(envelope);
    }
  }
};

export { SecureClient, SecureServer };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map