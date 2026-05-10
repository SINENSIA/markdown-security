const express = require('express');
const crypto = require('node:crypto');
const sanitizeHtml = require('sanitize-html');
const pino = require('pino');
const pinoHttp = require('pino-http');
const Ajv = require('ajv');
const openapi = require('./openapi.json');

const ajv = new Ajv({ strict: false });
const validateRequest = ajv.compile(openapi.components.schemas.ValidateRequest);

const REQUEST_ID_RE = /^[a-zA-Z0-9_.-]{1,128}$/;
const FRONT_MATTER_RE = /^---\n([\s\S]*?)\n---\n/;
const HTML_LIKE = /<\s*[a-zA-Z!/]/;

const logger = pino({
    level:
        process.env.LOG_LEVEL ||
        (process.env.NODE_ENV === 'test' ? 'silent' : 'info'),
});

const app = express();
app.set('query parser', 'simple');

app.use(
    pinoHttp({
        logger,
        genReqId: (req) => {
            const incoming = req.headers['x-request-id'];
            if (typeof incoming === 'string' && REQUEST_ID_RE.test(incoming)) {
                return incoming;
            }
            return crypto.randomUUID();
        },
    })
);

app.use((req, res, next) => {
    res.setHeader('x-request-id', req.id);
    next();
});

app.use(express.json({ limit: '256kb' }));

const validateBody = (body) => {
    const sanitized = sanitizeHtml(body, {
        allowedTags: [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'blockquote', 'ul', 'ol', 'li', 'br', 'hr',
            'strong', 'em', 'u', 's', 'b', 'i', 'mark', 'sub', 'sup',
            'pre', 'code', 'kbd', 'samp',
            'table', 'thead', 'tbody', 'tr', 'td', 'th',
            'a', 'img',
            'dl', 'dt', 'dd'
        ],
        allowedAttributes: {
            'a': ['href', 'title', 'target'],
            'img': ['src', 'alt', 'width', 'height'],
            'code': ['class']
        },
        allowedSchemes: ['http', 'https', 'mailto'],
        disallowedTagsMode: 'discard'
    });

    return { safe: body.trim() === sanitized.trim(), sanitized };
};

app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
});

app.get('/openapi.json', (_req, res) => {
    res.status(200).json(openapi);
});

app.post('/validate', (req, res) => {
    if (!validateRequest(req.body || {})) {
        return res.status(400).json({
            safe: false,
            error: 'Invalid request',
            details: validateRequest.errors.map((e) => ({
                field:
                    e.instancePath ||
                    (e.params && e.params.missingProperty
                        ? `/${e.params.missingProperty}`
                        : '/'),
                message: e.message,
            })),
        });
    }

    const { markdown } = req.body;

    const fmMatch = markdown.match(FRONT_MATTER_RE);
    const frontMatter = fmMatch ? fmMatch[1] : null;
    const body = fmMatch ? markdown.slice(fmMatch[0].length) : markdown;

    const bodyResult = validateBody(body);
    const frontMatterClean = frontMatter === null || !HTML_LIKE.test(frontMatter);
    const safe = bodyResult.safe && frontMatterClean;

    res.status(200).json({
        safe,
        message: safe ? "Markdown is safe" : "Markdown contains unsafe content",
        sanitized: bodyResult.sanitized,
        frontMatter
    });
});


if (require.main === module) {
    const PORT = process.env.PORT || 5001;
    app.listen(PORT, () => {
        logger.info({ port: Number(PORT) }, 'Server listening');
    });
}

module.exports = app;
