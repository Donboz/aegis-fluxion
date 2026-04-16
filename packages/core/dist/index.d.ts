import { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import WebSocket, { ClientOptions, ServerOptions } from 'ws';

declare const SECURE_SERVER_ADAPTER_MESSAGE_VERSION = 1;
type SecureChunkSourceValue = Buffer | Uint8Array | ArrayBuffer | string;
interface SecureServerMetricsSnapshot {
    serverId: string;
    timestampMs: number;
    uptimeSeconds: number;
    activeConnections: number;
    totalConnections: number;
    handshakeSuccessTotal: number;
    handshakeFailureTotal: number;
    resumeHandshakeSuccessTotal: number;
    resumeHandshakeFailureTotal: number;
    encryptedMessagesSentTotal: number;
    encryptedMessagesReceivedTotal: number;
    encryptedBytesSentTotal: number;
    encryptedBytesReceivedTotal: number;
    ddosBlockedTotal: number;
    ddosThrottledTotal: number;
    ddosDisconnectedTotal: number;
}
interface SecureEnvelope<TData = unknown> {
    event: string;
    data: TData;
}
type SecureBinaryPayload = Buffer | Uint8Array | Blob;
type SecureChunkedStreamSource = Buffer | Uint8Array | Readable | AsyncIterable<SecureChunkSourceValue>;
interface SecureChunkedStreamOptions {
    chunkSizeBytes?: number;
    metadata?: Record<string, unknown>;
    totalBytes?: number;
    signal?: AbortSignal;
}
interface SecureStreamSendResult {
    streamId: string;
    chunkCount: number;
    totalBytes: number;
}
interface SecureIncomingStreamInfo {
    streamId: string;
    event: string;
    metadata?: Record<string, unknown>;
    totalBytes?: number;
    startedAt: number;
}
type SecureServerStreamHandler = (stream: Readable, info: SecureIncomingStreamInfo, client: SecureServerClient) => void | Promise<void>;
type SecureClientStreamHandler = (stream: Readable, info: SecureIncomingStreamInfo) => void | Promise<void>;
interface SecureAckOptions {
    timeoutMs?: number;
}
type SecureAckCallback = (error: Error | null, response?: unknown) => void;
interface SecureServerHeartbeatOptions {
    enabled?: boolean;
    intervalMs?: number;
    timeoutMs?: number;
}
type SecureServerRateLimitAction = "throttle" | "disconnect";
interface SecureServerRateLimitOptions {
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
interface SecureServerSessionResumptionOptions {
    enabled?: boolean;
    ticketTtlMs?: number;
    maxCachedTickets?: number;
}
type SecureServerAdapterMessageScope = "broadcast" | "room";
interface SecureServerAdapterMessage {
    version: typeof SECURE_SERVER_ADAPTER_MESSAGE_VERSION;
    originServerId: string;
    scope: SecureServerAdapterMessageScope;
    event: string;
    data: unknown;
    emittedAt: number;
    room?: string;
}
interface SecureServerAdapter {
    attach: (server: SecureServer) => void | Promise<void>;
    publish: (message: SecureServerAdapterMessage) => void | Promise<void>;
    detach?: (server: SecureServer) => void | Promise<void>;
}
interface SecureServerOptions extends ServerOptions {
    heartbeat?: SecureServerHeartbeatOptions;
    rateLimit?: SecureServerRateLimitOptions;
    sessionResumption?: SecureServerSessionResumptionOptions;
    adapter?: SecureServerAdapter;
}
interface SecureClientReconnectOptions {
    enabled?: boolean;
    initialDelayMs?: number;
    maxDelayMs?: number;
    factor?: number;
    jitterRatio?: number;
    maxAttempts?: number | null;
}
interface SecureClientSessionResumptionOptions {
    enabled?: boolean;
    maxAcceptedTicketTtlMs?: number;
}
interface SecureClientOptions {
    protocols?: string | string[];
    wsOptions?: ClientOptions;
    autoConnect?: boolean;
    reconnect?: boolean | SecureClientReconnectOptions;
    sessionResumption?: boolean | SecureClientSessionResumptionOptions;
}
interface SecureServerClient {
    id: string;
    socket: WebSocket;
    request: IncomingMessage;
    metadata: ReadonlyMap<string, unknown>;
    emit: (event: string, data: unknown, callbackOrOptions?: SecureAckCallback | SecureAckOptions, maybeCallback?: SecureAckCallback) => boolean | Promise<unknown>;
    emitStream: (event: string, source: SecureChunkedStreamSource, options?: SecureChunkedStreamOptions) => Promise<SecureStreamSendResult>;
    join: (room: string) => boolean;
    leave: (room: string) => boolean;
    leaveAll: () => number;
}
interface SecureServerRoomOperator {
    emit: (event: string, data: unknown) => SecureServer;
}
type SecureErrorHandler = (error: Error) => void;
type SecureServerEventHandler = (data: unknown, client: SecureServerClient) => unknown | Promise<unknown>;
type SecureServerConnectionHandler = (client: SecureServerClient) => void;
type SecureServerDisconnectHandler = (client: SecureServerClient, code: number, reason: string) => void;
type SecureServerReadyHandler = (client: SecureServerClient) => void;
type SecureClientEventHandler = (data: unknown) => unknown | Promise<unknown>;
type SecureClientConnectHandler = () => void;
type SecureClientDisconnectHandler = (code: number, reason: string) => void;
type SecureClientReadyHandler = () => void;
type SecureServerLifecycleEvent = "connection" | "disconnect" | "ready" | "error";
type SecureClientLifecycleEvent = "connect" | "disconnect" | "ready" | "error";
interface SecureServerEventMap {
    connection: SecureServerConnectionHandler;
    disconnect: SecureServerDisconnectHandler;
    ready: SecureServerReadyHandler;
    error: SecureErrorHandler;
}
interface SecureClientEventMap {
    connect: SecureClientConnectHandler;
    disconnect: SecureClientDisconnectHandler;
    ready: SecureClientReadyHandler;
    error: SecureErrorHandler;
}
interface SecureServerConnectionMiddlewareContext {
    phase: "connection";
    socket: WebSocket;
    request: IncomingMessage;
    metadata: Map<string, unknown>;
}
interface SecureServerMessageMiddlewareContext {
    phase: "incoming" | "outgoing";
    client: SecureServerClient;
    event: string;
    data: unknown;
    metadata: Map<string, unknown>;
}
type SecureServerMiddlewareContext = SecureServerConnectionMiddlewareContext | SecureServerMessageMiddlewareContext;
type SecureServerMiddlewareNext = () => Promise<void>;
type SecureServerMiddleware = (context: SecureServerMiddlewareContext, next: SecureServerMiddlewareNext) => void | Promise<void>;
declare function normalizeSecureServerAdapterMessage(value: unknown): SecureServerAdapterMessage;
declare class SecureServer {
    private readonly instanceId;
    private readonly startedAtMs;
    private readonly socketServer;
    private adapter;
    private readonly heartbeatConfig;
    private readonly rateLimitConfig;
    private readonly sessionResumptionConfig;
    private heartbeatIntervalHandle;
    private readonly clientsById;
    private readonly clientIdBySocket;
    private readonly customEventHandlers;
    private readonly streamEventHandlers;
    private readonly connectionHandlers;
    private readonly disconnectHandlers;
    private readonly readyHandlers;
    private readonly errorHandlers;
    private readonly middlewareHandlers;
    private readonly handshakeStateBySocket;
    private readonly middlewareMetadataBySocket;
    private readonly sharedSecretBySocket;
    private readonly encryptionKeyBySocket;
    private readonly pendingPayloadsBySocket;
    private readonly incomingStreamsBySocket;
    private readonly pendingRpcRequestsBySocket;
    private readonly heartbeatStateBySocket;
    private readonly roomMembersByName;
    private readonly roomNamesByClientId;
    private readonly clientIpByClientId;
    private readonly rateLimitBucketsByClientId;
    private readonly rateLimitBucketsByIp;
    private readonly sessionTicketStore;
    private readonly telemetryCounters;
    constructor(options: SecureServerOptions);
    get clientCount(): number;
    get serverId(): string;
    get clients(): ReadonlyMap<string, SecureServerClient>;
    getMetrics(): SecureServerMetricsSnapshot;
    getMetricsPrometheus(): string;
    setAdapter(adapter: SecureServerAdapter | null): Promise<void>;
    handleAdapterMessage(message: unknown): Promise<void>;
    on(event: "connection", handler: SecureServerConnectionHandler): this;
    on(event: "disconnect", handler: SecureServerDisconnectHandler): this;
    on(event: "ready", handler: SecureServerReadyHandler): this;
    on(event: "error", handler: SecureErrorHandler): this;
    on(event: string, handler: SecureServerEventHandler): this;
    off(event: "connection", handler: SecureServerConnectionHandler): this;
    off(event: "disconnect", handler: SecureServerDisconnectHandler): this;
    off(event: "ready", handler: SecureServerReadyHandler): this;
    off(event: "error", handler: SecureErrorHandler): this;
    off(event: string, handler: SecureServerEventHandler): this;
    onStream(event: string, handler: SecureServerStreamHandler): this;
    offStream(event: string, handler: SecureServerStreamHandler): this;
    use(middleware: SecureServerMiddleware): this;
    emit(event: string, data: unknown): this;
    emitTo(clientId: string, event: string, data: unknown): boolean;
    emitTo(clientId: string, event: string, data: unknown, callback: SecureAckCallback): boolean;
    emitTo(clientId: string, event: string, data: unknown, options: SecureAckOptions): Promise<unknown>;
    emitTo(clientId: string, event: string, data: unknown, options: SecureAckOptions, callback: SecureAckCallback): boolean;
    emitStreamTo(clientId: string, event: string, source: SecureChunkedStreamSource, options?: SecureChunkedStreamOptions): Promise<SecureStreamSendResult>;
    to(room: string): SecureServerRoomOperator;
    close(code?: number, reason?: string): void;
    private recordHandshakeSuccess;
    private recordHandshakeFailure;
    private recordEncryptedMessageSent;
    private recordEncryptedMessageReceived;
    private recordDdosBlocked;
    private recordDdosThrottled;
    private resolveHeartbeatConfig;
    private resolveRateLimitConfig;
    private resolveSessionResumptionConfig;
    private pruneExpiredSessionTickets;
    private evictSessionTicketsIfNeeded;
    private getSessionTicket;
    private issueSessionTicket;
    private createRateLimitBucket;
    private getOrCreateRateLimitBucket;
    private updateRateLimitBucket;
    private pruneRateLimitBucketMap;
    private pruneRateLimitBuckets;
    private normalizeIpAddress;
    private resolveClientIp;
    private isIpStillConnected;
    private evaluateIncomingRateLimit;
    private startHeartbeatLoop;
    private stopHeartbeatLoop;
    private performHeartbeatSweep;
    private handleHeartbeatPong;
    private bindSocketServerEvents;
    private handleConnection;
    private handleIncomingMessage;
    private handleDisconnection;
    private dispatchCustomEvent;
    private getOrCreateIncomingServerStreams;
    private cleanupIncomingStreamsForSocket;
    private abortIncomingServerStream;
    private dispatchServerStreamEvent;
    private handleIncomingStreamStartFrame;
    private handleIncomingStreamChunkFrame;
    private handleIncomingStreamEndFrame;
    private handleIncomingStreamAbortFrame;
    private handleIncomingStreamFrame;
    private executeServerMiddleware;
    private applyMessageMiddleware;
    private resolveClientBySocket;
    private sendRaw;
    private sendEncryptedEnvelope;
    private sendRpcRequest;
    private handleRpcResponse;
    private handleRpcRequest;
    private executeRpcRequestHandler;
    private rejectPendingRpcRequests;
    private notifyConnection;
    private notifyReady;
    private notifyError;
    private createServerHandshakeState;
    private sendInternalHandshake;
    private sendResumeAck;
    private handleResumeHandshake;
    private handleInternalHandshake;
    private isClientHandshakeReady;
    private sendOrQueuePayload;
    private queuePayload;
    private flushQueuedPayloads;
    private createSecureServerClient;
    private emitLocally;
    private publishAdapterMessage;
    private normalizeRoomName;
    private joinClientToRoom;
    private leaveClientFromRoom;
    private leaveClientFromAllRooms;
    private emitToRoom;
}
declare class SecureClient {
    private readonly url;
    private readonly options;
    private socket;
    private readonly reconnectConfig;
    private readonly sessionResumptionConfig;
    private reconnectAttemptCount;
    private reconnectTimer;
    private isManualDisconnectRequested;
    private readonly customEventHandlers;
    private readonly streamEventHandlers;
    private readonly connectHandlers;
    private readonly disconnectHandlers;
    private readonly readyHandlers;
    private readonly errorHandlers;
    private handshakeState;
    private pendingPayloadQueue;
    private readonly pendingRpcRequests;
    private readonly incomingStreams;
    private sessionTicket;
    constructor(url: string, options?: SecureClientOptions);
    get readyState(): number | null;
    isConnected(): boolean;
    connect(): void;
    disconnect(code?: number, reason?: string): void;
    on(event: "connect", handler: SecureClientConnectHandler): this;
    on(event: "disconnect", handler: SecureClientDisconnectHandler): this;
    on(event: "ready", handler: SecureClientReadyHandler): this;
    on(event: "error", handler: SecureErrorHandler): this;
    on(event: string, handler: SecureClientEventHandler): this;
    off(event: "connect", handler: SecureClientConnectHandler): this;
    off(event: "disconnect", handler: SecureClientDisconnectHandler): this;
    off(event: "ready", handler: SecureClientReadyHandler): this;
    off(event: "error", handler: SecureErrorHandler): this;
    off(event: string, handler: SecureClientEventHandler): this;
    onStream(event: string, handler: SecureClientStreamHandler): this;
    offStream(event: string, handler: SecureClientStreamHandler): this;
    emit(event: string, data: unknown): boolean;
    emit(event: string, data: unknown, callback: SecureAckCallback): boolean;
    emit(event: string, data: unknown, options: SecureAckOptions): Promise<unknown>;
    emit(event: string, data: unknown, options: SecureAckOptions, callback: SecureAckCallback): boolean;
    emitStream(event: string, source: SecureChunkedStreamSource, options?: SecureChunkedStreamOptions): Promise<SecureStreamSendResult>;
    private resolveReconnectConfig;
    private resolveSessionResumptionConfig;
    private scheduleReconnect;
    private computeReconnectDelay;
    private clearReconnectTimer;
    private createSocket;
    private bindSocketEvents;
    private handleIncomingMessage;
    private handleDisconnect;
    private dispatchCustomEvent;
    private cleanupIncomingStreams;
    private abortIncomingClientStream;
    private dispatchClientStreamEvent;
    private handleIncomingClientStreamStartFrame;
    private handleIncomingClientStreamChunkFrame;
    private handleIncomingClientStreamEndFrame;
    private handleIncomingClientStreamAbortFrame;
    private handleIncomingStreamFrame;
    private notifyConnect;
    private notifyReady;
    private notifyError;
    private sendEncryptedEnvelope;
    private sendRpcRequest;
    private handleRpcResponse;
    private handleRpcRequest;
    private executeRpcRequestHandler;
    private rejectPendingRpcRequests;
    private handleSessionTicket;
    private createClientHandshakeState;
    private sendInternalHandshake;
    private shouldAttemptSessionResumption;
    private sendResumeHandshake;
    private completeFullHandshake;
    private fallbackToFullHandshake;
    private handleServerHelloHandshake;
    private handleResumeAckHandshake;
    private handleInternalHandshake;
    private isHandshakeReady;
    private flushPendingPayloadQueue;
}

export { type SecureAckCallback, type SecureAckOptions, type SecureBinaryPayload, type SecureChunkedStreamOptions, type SecureChunkedStreamSource, SecureClient, type SecureClientConnectHandler, type SecureClientDisconnectHandler, type SecureClientEventHandler, type SecureClientEventMap, type SecureClientLifecycleEvent, type SecureClientOptions, type SecureClientReadyHandler, type SecureClientReconnectOptions, type SecureClientSessionResumptionOptions, type SecureClientStreamHandler, type SecureEnvelope, type SecureErrorHandler, type SecureIncomingStreamInfo, SecureServer, type SecureServerAdapter, type SecureServerAdapterMessage, type SecureServerAdapterMessageScope, type SecureServerClient, type SecureServerConnectionHandler, type SecureServerConnectionMiddlewareContext, type SecureServerDisconnectHandler, type SecureServerEventHandler, type SecureServerEventMap, type SecureServerHeartbeatOptions, type SecureServerLifecycleEvent, type SecureServerMessageMiddlewareContext, type SecureServerMetricsSnapshot, type SecureServerMiddleware, type SecureServerMiddlewareContext, type SecureServerMiddlewareNext, type SecureServerOptions, type SecureServerRateLimitAction, type SecureServerRateLimitOptions, type SecureServerReadyHandler, type SecureServerRoomOperator, type SecureServerSessionResumptionOptions, type SecureServerStreamHandler, type SecureStreamSendResult, normalizeSecureServerAdapterMessage };
