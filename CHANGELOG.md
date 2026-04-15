<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] - 2026-04-15

### Added

- `SecureServer` now supports configurable rate limiting and DDoS shielding with per-connection and per-IP counters.
- New server options for overload protection:
  - `rateLimit.maxEventsPerConnection`
  - `rateLimit.maxEventsPerIp`
  - `rateLimit.action` (`"throttle" | "disconnect"`)
  - `rateLimit.throttleMs`, `rateLimit.maxThrottleMs`
  - `rateLimit.disconnectAfterViolations`, `rateLimit.disconnectCode`, `rateLimit.disconnectReason`
- Integration tests validating burst throttling/drop behavior and disconnect enforcement under flood conditions.

### Changed

- `@aegis-fluxion/core` bumped to `0.7.1`.
- `aegis-fluxion` (umbrella package) patch-bumped to `0.7.1` and now depends on `@aegis-fluxion/core@^0.7.1`.
- Versioning policy aligned to independent package releases, with umbrella patch bumps reflecting updated internals.

### Security

- Added server-side burst protection to slow or disconnect abusive peers before custom event handlers execute.
- Rate limiting is enforced for encrypted message ingress to reduce flood amplification and protect runtime stability.

## [0.7.0] - 2026-04-15

### Added

- New package `@aegis-fluxion/mcp-adapter` for MCP (Model Context Protocol) integration.
- `SecureMCPTransport` for carrying MCP JSON-RPC 2.0 traffic over encrypted `SecureClient` and `SecureServer` tunnels.
- Dual transport modes:
  - client mode (`SecureClient`)
  - server mode (`SecureServer` + explicit `clientId` session binding)
- MCP message guards and normalization helpers:
  - `normalizeSecureMCPMessage`
  - `isSecureMCPRequest`
  - `isSecureMCPNotification`
  - `isSecureMCPResponse`

### Changed

- Umbrella package `aegis-fluxion` now re-exports `@aegis-fluxion/mcp-adapter`.
- Monorepo scripts (`build`, `typecheck`, `test`, `clean`, `release:all`) now include the MCP adapter package.
- All package versions were synchronized to `0.7.0` for release consistency.

### Security

- MCP payload exchange now inherits existing ephemeral ECDH + AES-256-GCM protections from `@aegis-fluxion/core`.
- Server-side transport mode can be pinned to authenticated sockets by `clientId`, reducing cross-session routing risk.

## [0.6.0] - 2026-04-15

### Added

- Phase-based server middleware registration with `SecureServer.use(...)`.
- New middleware lifecycle contexts for `connection`, `incoming`, and `outgoing` phases.
- Per-socket middleware metadata pipeline (`Map<string, unknown>`) exposed as `SecureServerClient.metadata`.
- Integration tests for connection-level auth rejection and incoming/outgoing middleware payload interception.

### Changed

- Server connection flow is now middleware-aware before the `connection` event is dispatched.
- Incoming and outgoing envelopes now pass through middleware so event/data transformation can be centralized.
- Type definitions and public exports were expanded to include middleware context and helper types.

### Security

- Connection middleware rejection closes unauthorized sockets with WebSocket policy violation code `1008`.
- Existing ECDH + AES-256-GCM encryption model continues to protect all application payloads, including middleware-transformed messages.

## [0.5.0] - 2026-04-15

### Added

- Native binary payload support over encrypted channels for `Buffer`, `Uint8Array`, and `Blob` values.
- Recursive binary serialization for nested payloads so mixed JSON + binary objects are supported in both event and ACK flows.
- Binary transport integration tests for direct emit and encrypted ACK roundtrip scenarios.

### Changed

- Internal envelope serialization pipeline is now async-aware to support binary sources that require asynchronous extraction (for example `Blob`).
- Secure client/server encrypted send paths were updated to preserve payload type fidelity after decryption.

### Security

- Binary payloads are still protected end-to-end with the existing ECDH-derived AES-256-GCM channel.
- AES-GCM authentication continues to provide tamper detection for binary packets exactly as with JSON payloads.

## [0.4.0] - 2026-04-15

### Added

- Encrypted RPC-style ACK request/response flow over the existing AES-256-GCM tunnel.
- Promise-based ACK API for `SecureClient.emit(...)` and server-side `emitTo(...)`.
- Callback-based ACK API for Node-style interoperability.
- Per-request ACK timeout controls to fail fast on missing responses.
- New integration tests covering ACK success paths and timeout scenarios.

### Changed

- Extended server and client emit signatures to support optional ACK options and callbacks.
- Improved event pipeline to route internal RPC request/response frames safely.

### Security

- ACK payloads remain fully encrypted in transit using the same E2E envelope.
- Reserved internal RPC event names are protected against manual emit misuse.

## [0.3.0] - 2026-04-15

### Added

- Heartbeat Ping/Pong lifecycle to detect stale connections.
- Automatic reconnect with configurable exponential backoff and jitter.
- Re-handshake flow after reconnect to derive fresh encryption keys.
- Tests for zombie socket cleanup and reconnect resilience.

### Changed

- Client lifecycle now supports controlled reconnect attempts and delay policies.
- Server cleanup now clears per-socket cryptographic/session state on timeout.

### Security

- Zombie connection cleanup reduces risk of stale session reuse.
- Fresh key derivation after reconnect hardens long-running sessions.

## [0.2.0] - 2026-04-15

### Added

- Secure room primitives: `join`, `leave`, `leaveAll`, and `to(room).emit(...)`.
- Room membership tracking with server-side fanout routing.
- Integration tests for encrypted room messaging behavior.

### Changed

- Server client abstraction expanded with room management helpers.

### Security

- Room fanout continues to use encrypted payload delivery only.
- Room membership cleanup on disconnect prevents residual routing state.

## [0.1.0] - 2026-04-15

### Added

- Initial `@aegis-fluxion/core` release.
- Ephemeral ECDH handshake (`prime256v1`) for session key agreement.
- AES-256-GCM encrypted message envelopes for application events.
- Lifecycle events for connection, readiness, disconnection, and error handling.
- Basic encrypted server-client event communication model.

### Security

- Authenticated encryption with AES-GCM tamper detection.
- Shared secret derived per-session from ephemeral handshake keys.
