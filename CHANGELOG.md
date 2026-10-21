# Changelog

All notable changes to this fork are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Context-aware Create, Update and ResourceDelete operations preserve schema and wire checks without retaining the caller context or retrying writes after cancellation; nil resources are rejected before deletion, and the existing client interface and legacy entrypoints remain available.
- Context-aware schema construction and GET/ByID operations without retaining request contexts in reusable clients; legacy signatures and generated interfaces remain available.
- Pinned Go 1.27.3 development container and focused real HTTP cancellation, error-identity, authentication, and reuse controls; the Go 1.26.0 module floor and dependencies are retained.

### Changed

- Development and own-fork PR checks use a single rootless Podman dispatcher, maximum golangci-lint v2 diagnostics, read-only source and ephemeral caches; original module metadata is retained and existing lint findings remain blocking.
- Own-fork CI is restricted to same-repository PR heads; inherited Rancher release and Vault jobs are quarantined by repository guards before Actions activation.

### Fixed

- Context-aware non-success responses preserve API status and underlying body-read or cancellation causes while ordinary status errors retain their direct `*APIError` type.

### Security

- Both constructors reject malformed nonempty CA bundles before network access, including insecure mode, instead of returning a partial client with a nil error.

- `golang.org/x/net` v0.61.0 includes the HTTP/2 fixes for GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612 and GO-2026-6617. The previous exact-head scan reported static-call reachability; live exploitation was not established.
- `golang.org/x/mod` v0.42.0 includes the checksum database verification fixes for GO-2026-6179 and GO-2026-6180, previously reported at module-presence level only; required module graph and checksum changes retain the Go 1.26.0 floor and Go 1.27.3 development compiler.
