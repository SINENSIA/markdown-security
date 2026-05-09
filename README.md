# markdown-security

A small HTTP microservice that validates and sanitizes Markdown payloads against an HTML-tag allowlist. It is meant to sit between an untrusted producer (form, CMS, API caller) and any consumer that will render Markdown as HTML, so the consumer can rely on the body being free of script-bearing or otherwise dangerous tags.

The service is a single Express endpoint backed by [`sanitize-html`](https://www.npmjs.com/package/sanitize-html). It does not render Markdown to HTML; it inspects raw Markdown for embedded HTML, strips anything outside the allowlist, and tells the caller whether the input was modified.

## How it works

`POST /validate` accepts JSON of the form `{ "markdown": "..." }` and returns:

```json
{
  "safe": true,
  "message": "Markdown is safe",
  "sanitized": "...",
  "frontMatter": null
}
```

- `safe` is `true` only if sanitization made no changes to the body **and** no HTML-like content was detected in the front matter. Any disallowed tag, attribute, or URL scheme in either part will flip it to `false`.
- `sanitized` contains only the Markdown body, post-sanitization. It never contains the front-matter block.
- `frontMatter` is the raw YAML between the `---` markers, or `null` if no front matter was present. **It is returned untouched** — see the front-matter section below.
- `message` is a human-readable summary.

The status code is always `200` for well-formed requests, and `400` when the `markdown` field is missing or empty.

### Allowlist

Allowed tags: headings `h1`-`h6`, paragraphs and breaks (`p`, `br`, `hr`), lists (`ul`, `ol`, `li`, `dl`, `dt`, `dd`), text emphasis (`strong`, `em`, `u`, `s`, `b`, `i`, `mark`, `sub`, `sup`), code blocks (`pre`, `code`, `kbd`, `samp`), tables (`table`, `thead`, `tbody`, `tr`, `td`, `th`), blockquotes, images (`img`), and links (`a`).

Allowed attributes:

- `a`: `href`, `title`, `target`
- `img`: `src`, `alt`, `width`, `height`
- `code`: `class`

Allowed URL schemes for hrefs and image sources: `http`, `https`, `mailto`. Anything else (including `javascript:`, `data:`, `vbscript:`) is dropped.

### YAML front matter

A leading YAML block of the form `---\n...\n---\n` is detected and exposed in a separate `frontMatter` field. The block contents are **not** run through `sanitize-html` — they are returned to the caller raw. The reason is that YAML is a data format, not a display format, and trying to sanitize it as HTML produces false positives on legitimate values.

What the service *does* check: if the front-matter content contains an HTML-like token (`<` immediately followed by a letter, `!`, or `/`), `safe` is set to `false`. That covers the realistic threat model — an attacker smuggling `<script>` or `<iframe>` past the sanitizer by hiding it in metadata. It does not catch every possible misuse, so:

> **If you intend to render any front-matter value as HTML, sanitize it on the consumer side.** Treat `frontMatter` as untrusted input.

## Quickstart

```bash
npm install
npm start              # listens on http://localhost:5001
npm test               # runs the Jest suite
```

```bash
curl -s -X POST http://localhost:5001/validate \
  -H 'content-type: application/json' \
  -d '{"markdown":"# Hello\n\n<script>alert(1)</script>"}'
```

```json
{
  "safe": false,
  "message": "Markdown contains unsafe content",
  "sanitized": "# Hello\n\n",
  "frontMatter": null
}
```

## Docker

```bash
docker build -t markdown-security .
docker run --rm -p 5001:5001 markdown-security
```

The image is built on `node:24-alpine`, runs as the unprivileged `node` user, and ships a `HEALTHCHECK` that exercises `/validate`. The bundled `.dockerignore` keeps `.git`, `.env`, tests and CI artefacts out of the image.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PORT`  | `5001`  | TCP port the HTTP server binds to. |

The JSON body limit is fixed at `256kb`. Markdown larger than that is rejected by Express with a `413` before reaching the handler. Adjust `express.json({ limit: ... })` in `server.js` if you need more.

## Security notes

- **Allowlist, not denylist.** New tags are blocked by default. To extend the surface, edit the `allowedTags` / `allowedAttributes` arrays in `server.js` and add a regression test.
- **Front matter is exposed raw, not trusted.** It is returned in its own `frontMatter` field, never inside `sanitized`. A coarse HTML-like check decides `safe`, but the consumer must sanitize any front-matter value it intends to render as HTML.
- **`query parser` is set to `simple`.** Express's default `qs`-based parser has shipped two array-limit DoS bypasses (`GHSA-w7fw-mjwx-w883`, `GHSA-6rw7-vpxm-498p`); the simple parser is not affected. Do not change this without re-reviewing those advisories.
- **Body size cap.** `express.json({ limit: '256kb' })` is the first line of defence against payload-amplification attacks against `sanitize-html`.
- **No rate limiting or auth.** This service expects to live behind a gateway that handles those concerns. If you expose it directly, put a reverse proxy in front.

`npm audit` reports zero vulnerabilities at the time of writing (May 2026, against `express@5`, `sanitize-html@2.17`, `jest@30`, `supertest@7.2`).

## Project layout

```
server.js                 Express app + /validate handler. Single source of truth.
tests/validation.test.js  Jest + Supertest suite covering happy path and rejection cases.
Dockerfile, .dockerignore Container build.
```

## License

MIT - see [LICENSE](LICENSE).
