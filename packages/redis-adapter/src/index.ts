import {
  normalizeSecureServerAdapterMessage,
  type SecureServer,
  type SecureServerAdapter,
  type SecureServerAdapterMessage
} from "@aegis-fluxion/core";
import { createClient, type RedisClientType } from "redis";

const DEFAULT_CHANNEL = "aegis-fluxion:secure-server:cluster:v1";

export type RedisPubSubClient = RedisClientType;

export interface RedisSecureServerAdapterOptions {
  redisUrl?: string;
  channel?: string;
  publisher?: RedisPubSubClient;
  subscriber?: RedisPubSubClient;
  onError?: (error: Error) => void;
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

export class RedisSecureServerAdapter implements SecureServerAdapter {
  private readonly channel: string;

  private readonly publisher: RedisPubSubClient;

  private readonly subscriber: RedisPubSubClient;

  private readonly ownsPublisher: boolean;

  private readonly ownsSubscriber: boolean;

  private readonly onError: ((error: Error) => void) | null;

  private attachedServer: SecureServer | null = null;

  private subscribed = false;

  public constructor(options: RedisSecureServerAdapterOptions = {}) {
    const channel = options.channel?.trim() || DEFAULT_CHANNEL;

    if (channel.length === 0) {
      throw new Error("Redis adapter channel must be a non-empty string.");
    }

    this.channel = channel;
    this.onError = options.onError ?? null;

    this.ownsPublisher = options.publisher === undefined;
    this.ownsSubscriber = options.subscriber === undefined;

    this.publisher =
      options.publisher ??
      createClient({
        ...(options.redisUrl ? { url: options.redisUrl } : {})
      });

    this.subscriber =
      options.subscriber ??
      createClient({
        ...(options.redisUrl ? { url: options.redisUrl } : {})
      });
  }

  public async attach(server: SecureServer): Promise<void> {
    if (this.attachedServer && this.attachedServer !== server) {
      throw new Error("RedisSecureServerAdapter is already attached to another SecureServer.");
    }

    this.attachedServer = server;

    await this.ensureConnected();

    if (this.subscribed) {
      return;
    }

    await this.subscriber.subscribe(this.channel, (rawMessage: string) => {
      void this.handleIncomingMessage(rawMessage);
    });

    this.subscribed = true;
  }

  public async publish(message: SecureServerAdapterMessage): Promise<void> {
    const normalizedMessage = normalizeSecureServerAdapterMessage(message);
    await this.ensurePublisherConnected();

    await this.publisher.publish(this.channel, JSON.stringify(normalizedMessage));
  }

  public async detach(server: SecureServer): Promise<void> {
    if (this.attachedServer && this.attachedServer !== server) {
      return;
    }

    this.attachedServer = null;

    if (this.subscribed && this.subscriber.isOpen) {
      await this.subscriber.unsubscribe(this.channel);
    }

    this.subscribed = false;

    await this.closeOwnedClients();
  }

  private async ensureConnected(): Promise<void> {
    await Promise.all([this.ensurePublisherConnected(), this.ensureSubscriberConnected()]);
  }

  private async ensurePublisherConnected(): Promise<void> {
    if (!this.publisher.isOpen) {
      await this.publisher.connect();
    }
  }

  private async ensureSubscriberConnected(): Promise<void> {
    if (!this.subscriber.isOpen) {
      await this.subscriber.connect();
    }
  }

  private async closeOwnedClients(): Promise<void> {
    if (this.ownsSubscriber && this.subscriber.isOpen) {
      await this.subscriber.quit();
    }

    if (this.ownsPublisher && this.publisher.isOpen) {
      await this.publisher.quit();
    }
  }

  private async handleIncomingMessage(rawMessage: string): Promise<void> {
    if (!this.attachedServer) {
      return;
    }

    try {
      const parsedMessage = JSON.parse(rawMessage) as unknown;
      const normalizedMessage = normalizeSecureServerAdapterMessage(parsedMessage);
      await this.attachedServer.handleAdapterMessage(normalizedMessage);
    } catch (error) {
      this.onError?.(
        normalizeToError(error, "Redis adapter failed to process incoming Pub/Sub message.")
      );
    }
  }
}

export {
  DEFAULT_CHANNEL as REDIS_SECURE_SERVER_ADAPTER_DEFAULT_CHANNEL
};
