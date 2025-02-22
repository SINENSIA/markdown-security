const express = require('express');
const sanitizeHtml = require('sanitize-html');

const app = express();
app.use(express.json());

const validateMarkdown = (markdown) => {
    return sanitizeHtml(markdown, {
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
};

const extractFrontMatter = (markdown) => {
    const match = markdown.match(/^---\n([\s\S]*?)\n---\n/);
    return match ? match[0] : '';
};

app.post('/validate', (req, res) => {
    let { markdown } = req.body;

    if (!markdown) {
        return res.status(400).json({ safe: false, error: "No Markdown provided" });
    }

    markdown = String(markdown);
    let frontMatter = extractFrontMatter(markdown);
    markdown = markdown.replace(/^---\n([\s\S]*?)\n---\n/, '');
    let sanitized = validateMarkdown(markdown);
    let finalMarkdown = frontMatter ? `${frontMatter}\n${sanitized}` : sanitized;

    if (sanitized !== markdown) {
        return res.status(400).json({ safe: false, error: "Malicious content detected", sanitized: finalMarkdown });
    }

    res.json({ safe: true, message: "Markdown is safe", sanitized: finalMarkdown });
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Security Service running on port ${PORT}`));