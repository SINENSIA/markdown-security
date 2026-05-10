# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-05-10

### Added
- `GET /health` liveness probe returning `{ "status": "ok" }`. The Docker `HEALTHCHECK` now hits this endpoint instead of `POST /validate`, removing the sanitizer call from the probe path.
- `GET /openapi.json` serves an OpenAPI 3.1 specification covering every public endpoint, request/response schemas, status codes, and the `x-request-id` header.
- Structured JSON logging via `pino` + `pino-http`. New `LOG_LEVEL` env var (default `info`, forced to `silent` under `NODE_ENV=test`).
- `x-request-id` correlation header. Echoed when the incoming value matches `^[a-zA-Z0-9_.-]{1,128}$`, otherwise a server-generated UUID. Surfaced on every endpoint and included in every log line.
- Property-based fuzzing suite (`fast-check`) exercising sanitizer invariants: no dangerous tags ever leak to `sanitized`, sanitization is idempotent, the front matter never bleeds into `sanitized`, and HTML inside the front matter always flips `safe` to `false`.
- CI workflow on GitHub Actions: test matrix (Node 20/22/24), `npm audit --audit-level=high --omit=dev` job, CodeQL with `security-extended` queries, concurrency cancellation on PR pushes.
- Dependabot configuration for `npm` and `github-actions` ecosystems.
- `SECURITY.md` with supported versions and private vulnerability reporting through GitHub Security Advisories.
- `engines: { node: ">=20" }` in `package.json` to align the documented floor with the CI matrix.
- Regression tests for the 256kb body limit (413) and `javascript:` / `data:` / `vbscript:` URL scheme stripping.

### Changed
- `Dockerfile` `HEALTHCHECK` switched from POSTing to `/validate` to GETting `/health`.
- Test descriptions and code comments translated to English for end-to-end consistency.
- README updated to document the new endpoints, the `LOG_LEVEL` knob, and the request-correlation header.

### Removed
- Dead `PROHIBITED_TAGS` constant in `server.js`. The allowlist passed to `sanitize-html` was always the source of truth.

## [2.0.0] - 2026-05-09

### Added
- Dedicated `frontMatter` field in the `/validate` response, exposing the YAML front matter raw and untrusted alongside the sanitized body.

### Changed
- **Breaking**: `POST /validate` no longer concatenates YAML front matter back into `sanitized`. Front matter is returned in `frontMatter`, and `safe` reflects both the body sanitization result and an HTML-like check against the front matter.

  *Migration*: consumers that read the YAML block from `sanitized` must now read it from `frontMatter`. If front matter is rendered as HTML downstream, sanitize it on the consumer side.

### Fixed
- HTML inside the YAML front-matter block bypassed the sanitizer in 1.x while `safe` still reported `true`.
- `README.md` rewritten as UTF-8 (was previously corrupted as UTF-16 LE).

### Security
- `qs` array-limit DoS bypass mitigated via `app.set('query parser', 'simple')` (`GHSA-w7fw-mjwx-w883`, `GHSA-6rw7-vpxm-498p`).
- Container hardened: runs as the unprivileged `node` user, ships a `HEALTHCHECK`, includes a `.dockerignore`.

[Unreleased]: https://github.com/SINENSIA/markdown-security/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/SINENSIA/markdown-security/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/SINENSIA/markdown-security/releases/tag/v2.0.0
