import type { SecureClientEventHandler, SecureServerClient } from "@aegis-fluxion/core";
import { SecureClient, SecureServer } from "@aegis-fluxion/core";

const DEFAULT_MCP_CHANNEL = "mcp:jsonrpc";
const DEFAULT_CLIENT_START_TIMEOUT_MS = 10_000;
const DEFAULT_CLOSE_CODE = 1000;
const DEFAULT_CLOSE_REASON = "Secure MCP transport closed.";

export type SecureMCPMessageId = string | number | null;

export interface SecureMCPErrorObject {
  code: number;
  message: string;
  data?: unknown;
}

export interface SecureMCPRequest {
  jsonrpc: "2.0";
  id: SecureMCPMessageId;
  method: string;
  params?: unknown;
}

export interface SecureMCPNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface SecureMCPResponse {
  jsonrpc: "2.0";
  id: SecureMCPMessageId;
  result?: unknown;
  error?: SecureMCPErrorObject;
}

export type SecureMCPMessage =
  | SecureMCPRequest
  | SecureMCPNotification
  | SecureMCPResponse;

export interface SecureMCPTransportLike {
  start(): Promise<void>;
  send(message: SecureMCPMessage): Promise<void>;
  close(): Promise<void>;
  onmessage?: (message: SecureMCPMessage) => void | Promise<void>;
  onerror?: (error: Error) => void | Promise<void>;
  onclose?: () => void | Promise<void>;
}

interface SecureMCPTransportBaseOptions {
  channel?: string;
}

export interface SecureMCPClientTransportOptions
  extends SecureMCPTransportBaseOptions {
  mode: "client";
  client: SecureClient;
  connectTimeoutMs?: number;
}

export interface SecureMCPServerTransportOptions
  extends SecureMCPTransportBaseOptions {
  mode: "server";
  server: SecureServer;
  clientId: string;
  closeCode?: number;
  closeReason?: string;
}

export type SecureMCPTransportOptions =
  | SecureMCPClientTransportOptions
  | SecureMCPServerTransportOptions;

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwnProperty(
  value: Record<string, unknown>,
  key: string
): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
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

function normalizeMCPMessageId(
  value: unknown,
  label: string
): SecureMCPMessageId {
  if (typeof value === "string" || typeof value === "number" || value === null) {
    return value;
  }

  throw new Error(`${label} must be a string, number, or null.`);
}

function normalizeMCPErrorObject(value: unknown): SecureMCPErrorObject {
  if (!isObjectRecord(value)) {
    throw new Error("MCP response error must be an object.");
  }

  if (typeof value.code !== "number" || !Number.isFinite(value.code)) {
    throw new Error("MCP response error.code must be a finite number.");
  }

  if (typeof value.message !== "string" || value.message.trim().length === 0) {
    throw new Error("MCP response error.message must be a non-empty string.");
  }

  const normalizedError: SecureMCPErrorObject = {
    code: value.code,
    message: value.message
  };

  if (hasOwnProperty(value, "data")) {
    normalizedError.data = value.data;
  }

  return normalizedError;
}

function decodeMessageCandidate(candidate: unknown): unknown {
  if (typeof candidate !== "string") {
    return candidate;
  }

  try {
    return JSON.parse(candidate) as unknown;
  } catch (error) {
    throw normalizeToError(error, "Incoming MCP payload is not valid JSON.");
  }
}

export function normalizeSecureMCPMessage(candidate: unknown): SecureMCPMessage {
  const decodedCandidate = decodeMessageCandidate(candidate);

  if (!isObjectRecord(decodedCandidate)) {
    throw new Error("MCP message must be a JSON object.");
  }

  if (decodedCandidate.jsonrpc !== "2.0") {
    throw new Error("MCP message jsonrpc must be \"2.0\".");
  }

  const hasMethod = hasOwnProperty(decodedCandidate, "method");
  const hasId = hasOwnProperty(decodedCandidate, "id");
  const hasParams = hasOwnProperty(decodedCandidate, "params");

  if (hasMethod) {
    if (
      typeof decodedCandidate.method !== "string" ||
      decodedCandidate.method.trim().length === 0
    ) {
      throw new Error("MCP message method must be a non-empty string.");
    }

    if (!hasId) {
      const notification: SecureMCPNotification = {
        jsonrpc: "2.0",
        method: decodedCandidate.method
      };

      if (hasParams) {
        notification.params = decodedCandidate.params;
      }

      return notification;
    }

    const request: SecureMCPRequest = {
      jsonrpc: "2.0",
      id: normalizeMCPMessageId(decodedCandidate.id, "MCP request id"),
      method: decodedCandidate.method
    };

    if (hasParams) {
      request.params = decodedCandidate.params;
    }

    return request;
  }

  if (!hasId) {
    throw new Error("MCP response message must include an id field.");
  }

  const hasResult = hasOwnProperty(decodedCandidate, "result");
  const hasError = hasOwnProperty(decodedCandidate, "error");

  if (hasResult === hasError) {
    throw new Error("MCP response must include exactly one of result or error.");
  }

  const response: SecureMCPResponse = {
    jsonrpc: "2.0",
    id: normalizeMCPMessageId(decodedCandidate.id, "MCP response id")
  };

  if (hasResult) {
    response.result = decodedCandidate.result;
    return response;
  }

  response.error = normalizeMCPErrorObject(decodedCandidate.error);
  return response;
}

export function isSecureMCPRequest(message: SecureMCPMessage): message is SecureMCPRequest {
  return "method" in message && "id" in message;
}

export function isSecureMCPNotification(
  message: SecureMCPMessage
): message is SecureMCPNotification {
  return "method" in message && !("id" in message);
}

export function isSecureMCPResponse(message: SecureMCPMessage): message is SecureMCPResponse {
  return !("method" in message);
}

export class SecureMCPTransport implements SecureMCPTransportLike {
  public onmessage?: (message: SecureMCPMessage) => void | Promise<void>;

  public onerror?: (error: Error) => void | Promise<void>;

  public onclose?: () => void | Promise<void>;

  private readonly channel: string;

  private readonly clientStartTimeoutMs: number;

  private started = false;

  private closed = false;

  private closeEmitted = false;

  private clientMessageHandler: SecureClientEventHandler | undefined;

  private clientErrorHandler: ((error: Error) => void) | undefined;

  private clientDisconnectHandler:
    | ((code: number, reason: string) => void)
    | undefined;

  private serverMessageHandler:
    | ((data: unknown, client: SecureServerClient) => void)
    | undefined;

  private serverErrorHandler: ((error: Error) => void) | undefined;

  private serverDisconnectHandler:
    |
    ((
    client: SecureServerClient,
    code: number,
    reason: string
  ) => void)
    | undefined;

  public constructor(private readonly options: SecureMCPTransportOptions) {
    this.channel = options.channel?.trim() || DEFAULT_MCP_CHANNEL;

    if (this.channel.length === 0) {
      throw new Error("SecureMCPTransport channel must be a non-empty string.");
    }

    if (options.mode === "client") {
      const timeoutMs = options.connectTimeoutMs ?? DEFAULT_CLIENT_START_TIMEOUT_MS;

      if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
        throw new Error("SecureMCPTransport client connectTimeoutMs must be a positive number.");
      }

      this.clientStartTimeoutMs = timeoutMs;
      return;
    }

    if (options.clientId.trim().length === 0) {
      throw new Error("SecureMCPTransport server clientId must be a non-empty string.");
    }

    this.clientStartTimeoutMs = DEFAULT_CLIENT_START_TIMEOUT_MS;
  }

  public async start(): Promise<void> {
    if (this.closed) {
      throw new Error("SecureMCPTransport cannot be started after it was closed.");
    }

    if (this.started) {
      return;
    }

    if (this.options.mode === "client") {
      await this.startClientMode(this.options);
      this.started = true;
      return;
    }

    this.startServerMode(this.options);
    this.started = true;
  }

  public async send(message: SecureMCPMessage): Promise<void> {
    if (!this.started) {
      throw new Error("SecureMCPTransport must be started before send().");
    }

    if (this.closed) {
      throw new Error("SecureMCPTransport is closed.");
    }

    const normalizedMessage = normalizeSecureMCPMessage(message);

    if (this.options.mode === "client") {
      const emitResult = this.options.client.emit(this.channel, normalizedMessage);

      if (typeof emitResult === "boolean") {
        if (!emitResult) {
          throw new Error("SecureMCPTransport client failed to emit MCP payload.");
        }

        return;
      }

      await emitResult;
      return;
    }

    const emitResult = this.options.server.emitTo(
      this.options.clientId,
      this.channel,
      normalizedMessage
    );

    if (typeof emitResult === "boolean") {
      if (!emitResult) {
        throw new Error(
          `SecureMCPTransport server failed to emit MCP payload to client ${this.options.clientId}.`
        );
      }

      return;
    }

    await emitResult;
  }

  public async close(): Promise<void> {
    if (this.closed) {
      return;
    }

    this.closed = true;
    this.detachListeners();

    if (this.options.mode === "client") {
      this.options.client.disconnect();
    } else {
      const targetClient = this.options.server.clients.get(this.options.clientId);

      if (targetClient) {
        const closeCode = this.options.closeCode ?? DEFAULT_CLOSE_CODE;
        const closeReason = this.options.closeReason ?? DEFAULT_CLOSE_REASON;
        targetClient.socket.close(closeCode, closeReason);
      }
    }

    await this.emitClose();
  }

  private async startClientMode(
    options: SecureMCPClientTransportOptions
  ): Promise<void> {
    this.clientMessageHandler = (payload: unknown): void => {
      void this.handleIncomingPayload(payload);
    };

    this.clientErrorHandler = (error: Error): void => {
      void this.emitError(
        normalizeToError(error, "SecureMCPTransport client reported an error.")
      );
    };

    this.clientDisconnectHandler = (): void => {
      void this.handlePeerDisconnect();
    };

    options.client.on(this.channel, this.clientMessageHandler);
    options.client.on("error", this.clientErrorHandler);
    options.client.on("disconnect", this.clientDisconnectHandler);

    if (options.client.isConnected()) {
      return;
    }

    const readyPromise = this.awaitClientReady(options.client);
    options.client.connect();
    await readyPromise;
  }

  private startServerMode(options: SecureMCPServerTransportOptions): void {
    this.serverMessageHandler = (payload: unknown, client: SecureServerClient): void => {
      if (client.id !== options.clientId) {
        return;
      }

      void this.handleIncomingPayload(payload);
    };

    this.serverErrorHandler = (error: Error): void => {
      void this.emitError(
        normalizeToError(error, "SecureMCPTransport server reported an error.")
      );
    };

    this.serverDisconnectHandler = (client: SecureServerClient): void => {
      if (client.id !== options.clientId) {
        return;
      }

      void this.handlePeerDisconnect();
    };

    options.server.on(this.channel, this.serverMessageHandler);
    options.server.on("error", this.serverErrorHandler);
    options.server.on("disconnect", this.serverDisconnectHandler);
  }

  private awaitClientReady(client: SecureClient): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        cleanup();
        reject(
          new Error(
            `SecureMCPTransport client did not emit \"ready\" within ${this.clientStartTimeoutMs}ms.`
          )
        );
      }, this.clientStartTimeoutMs);

      timeoutHandle.unref?.();

      const onReady = (): void => {
        cleanup();
        resolve();
      };

      const onError = (error: Error): void => {
        cleanup();
        reject(
          normalizeToError(
            error,
            "SecureMCPTransport client emitted an error before ready."
          )
        );
      };

      const onDisconnect = (): void => {
        cleanup();
        reject(
          new Error("SecureMCPTransport client disconnected before becoming ready.")
        );
      };

      const cleanup = (): void => {
        clearTimeout(timeoutHandle);
        client.off("ready", onReady);
        client.off("error", onError);
        client.off("disconnect", onDisconnect);
      };

      client.on("ready", onReady);
      client.on("error", onError);
      client.on("disconnect", onDisconnect);
    });
  }

  private async handleIncomingPayload(payload: unknown): Promise<void> {
    try {
      const message = normalizeSecureMCPMessage(payload);

      if (!this.onmessage) {
        return;
      }

      await Promise.resolve(this.onmessage(message));
    } catch (error) {
      await this.emitError(
        normalizeToError(error, "SecureMCPTransport rejected an incoming MCP payload.")
      );
    }
  }

  private async handlePeerDisconnect(): Promise<void> {
    if (this.closed) {
      return;
    }

    this.closed = true;
    this.detachListeners();
    await this.emitClose();
  }

  private detachListeners(): void {
    if (this.options.mode === "client") {
      if (this.clientMessageHandler) {
        this.options.client.off(this.channel, this.clientMessageHandler);
      }

      if (this.clientErrorHandler) {
        this.options.client.off("error", this.clientErrorHandler);
      }

      if (this.clientDisconnectHandler) {
        this.options.client.off("disconnect", this.clientDisconnectHandler);
      }

      this.clientMessageHandler = undefined;
      this.clientErrorHandler = undefined;
      this.clientDisconnectHandler = undefined;
      return;
    }

    if (this.serverMessageHandler) {
      this.options.server.off(this.channel, this.serverMessageHandler);
    }

    if (this.serverErrorHandler) {
      this.options.server.off("error", this.serverErrorHandler);
    }

    if (this.serverDisconnectHandler) {
      this.options.server.off("disconnect", this.serverDisconnectHandler);
    }

    this.serverMessageHandler = undefined;
    this.serverErrorHandler = undefined;
    this.serverDisconnectHandler = undefined;
  }

  private async emitError(error: Error): Promise<void> {
    if (!this.onerror) {
      return;
    }

    try {
      await Promise.resolve(this.onerror(error));
    } catch {
      // Error callbacks must not throw into transport lifecycle.
    }
  }

  private async emitClose(): Promise<void> {
    if (this.closeEmitted) {
      return;
    }

    this.closeEmitted = true;

    if (!this.onclose) {
      return;
    }

    try {
      await Promise.resolve(this.onclose());
    } catch {
      // Close callbacks must not throw into transport lifecycle.
    }
  }
}

export { DEFAULT_MCP_CHANNEL as SECURE_MCP_DEFAULT_CHANNEL };