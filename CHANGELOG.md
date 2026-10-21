# Changelog

All notable changes to this fork are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Context-aware schema construction and GET/ByID operations without retaining request contexts in reusable clients; legacy signatures and generated interfaces remain available.
- Pinned Go 1.27.3 development container and focused real HTTP cancellation, error-identity, authentication, and reuse controls; the Go 1.26.0 module floor and dependencies are retained.

### Fixed

- Context-aware non-success responses preserve API status and underlying body-read or cancellation causes while ordinary status errors retain their direct `*APIError` type.

### Security

- Both constructors reject malformed nonempty CA bundles before network access, including insecure mode, instead of returning a partial client with a nil error.
