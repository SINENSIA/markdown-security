const express = require('express');
const sanitizeHtml = require('sanitize-html');

const app = express();
app.set('query parser', 'simple');
app.use(express.json({ limit: '256kb' }));

const FRONT_MATTER_RE = /^---\n([\s\S]*?)\n---\n/;
const HTML_LIKE = /<\s*[a-zA-Z!/]/;

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

app.post('/validate', (req, res) => {
    let { markdown } = req.body;

    if (!markdown) {
        return res.status(400).json({ safe: false, error: "No Markdown provided" });
    }

    markdown = String(markdown);

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
        console.log(`Server listening on http://localhost:${PORT}`);
    });
}

module.exports = app;
