import { IncomingMessage } from 'node:http';
import WebSocket, { ClientOptions, ServerOptions } from 'ws';

interface SecureEnvelope<TData = unknown> {
    event: string;
    data: TData;
}
interface SecureServerHeartbeatOptions {
    enabled?: boolean;
    intervalMs?: number;
    timeoutMs?: number;
}
interface SecureServerOptions extends ServerOptions {
    heartbeat?: SecureServerHeartbeatOptions;
}
interface SecureClientReconnectOptions {
    enabled?: boolean;
    initialDelayMs?: number;
    maxDelayMs?: number;
    factor?: number;
    jitterRatio?: number;
    maxAttempts?: number | null;
}
interface SecureClientOptions {
    protocols?: string | string[];
    wsOptions?: ClientOptions;
    autoConnect?: boolean;
    reconnect?: boolean | SecureClientReconnectOptions;
}
interface SecureServerClient {
    id: string;
    socket: WebSocket;
    request: IncomingMessage;
    join: (room: string) => boolean;
    leave: (room: string) => boolean;
    leaveAll: () => number;
}
interface SecureServerRoomOperator {
    emit: (event: string, data: unknown) => SecureServer;
}
type SecureErrorHandler = (error: Error) => void;
type SecureServerEventHandler = (data: unknown, client: SecureServerClient) => void;
type SecureServerConnectionHandler = (client: SecureServerClient) => void;
type SecureServerDisconnectHandler = (client: SecureServerClient, code: number, reason: string) => void;
type SecureServerReadyHandler = (client: SecureServerClient) => void;
type SecureClientEventHandler = (data: unknown) => void;
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
declare class SecureServer {
    private readonly socketServer;
    private readonly heartbeatConfig;
    private heartbeatIntervalHandle;
    private readonly clientsById;
    private readonly clientIdBySocket;
    private readonly customEventHandlers;
    private readonly connectionHandlers;
    private readonly disconnectHandlers;
    private readonly readyHandlers;
    private readonly errorHandlers;
    private readonly handshakeStateBySocket;
    private readonly sharedSecretBySocket;
    private readonly encryptionKeyBySocket;
    private readonly pendingPayloadsBySocket;
    private readonly heartbeatStateBySocket;
    private readonly roomMembersByName;
    private readonly roomNamesByClientId;
    constructor(options: SecureServerOptions);
    get clientCount(): number;
    get clients(): ReadonlyMap<string, SecureServerClient>;
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
    emit(event: string, data: unknown): this;
    emitTo(clientId: string, event: string, data: unknown): boolean;
    to(room: string): SecureServerRoomOperator;
    close(code?: number, reason?: string): void;
    private resolveHeartbeatConfig;
    private startHeartbeatLoop;
    private stopHeartbeatLoop;
    private performHeartbeatSweep;
    private handleHeartbeatPong;
    private bindSocketServerEvents;
    private handleConnection;
    private handleIncomingMessage;
    private handleDisconnection;
    private dispatchCustomEvent;
    private sendRaw;
    private sendEncryptedEnvelope;
    private notifyConnection;
    private notifyReady;
    private notifyError;
    private createServerHandshakeState;
    private sendInternalHandshake;
    private handleInternalHandshake;
    private isClientHandshakeReady;
    private sendOrQueuePayload;
    private queuePayload;
    private flushQueuedPayloads;
    private createSecureServerClient;
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
    private reconnectAttemptCount;
    private reconnectTimer;
    private isManualDisconnectRequested;
    private readonly customEventHandlers;
    private readonly connectHandlers;
    private readonly disconnectHandlers;
    private readonly readyHandlers;
    private readonly errorHandlers;
    private handshakeState;
    private pendingPayloadQueue;
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
    emit(event: string, data: unknown): boolean;
    private resolveReconnectConfig;
    private scheduleReconnect;
    private computeReconnectDelay;
    private clearReconnectTimer;
    private createSocket;
    private bindSocketEvents;
    private handleIncomingMessage;
    private handleDisconnect;
    private dispatchCustomEvent;
    private notifyConnect;
    private notifyReady;
    private notifyError;
    private sendEncryptedEnvelope;
    private createClientHandshakeState;
    private sendInternalHandshake;
    private handleInternalHandshake;
    private isHandshakeReady;
    private flushPendingPayloadQueue;
}

export { SecureClient, type SecureClientConnectHandler, type SecureClientDisconnectHandler, type SecureClientEventHandler, type SecureClientEventMap, type SecureClientLifecycleEvent, type SecureClientOptions, type SecureClientReadyHandler, type SecureClientReconnectOptions, type SecureEnvelope, type SecureErrorHandler, SecureServer, type SecureServerClient, type SecureServerConnectionHandler, type SecureServerDisconnectHandler, type SecureServerEventHandler, type SecureServerEventMap, type SecureServerHeartbeatOptions, type SecureServerLifecycleEvent, type SecureServerOptions, type SecureServerReadyHandler, type SecureServerRoomOperator };
