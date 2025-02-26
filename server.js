const express = require('express');
const sanitizeHtml = require('sanitize-html');

const app = express();
app.use(express.json());

const PROHIBITED_TAGS = ['script', 'iframe', 'object', 'embed', 'form', 'meta', 'link'];

const validateMarkdown = (markdown) => {
    // Buscar etiquetas prohibidas antes de sanitizar
    const regex = new RegExp(`<(${PROHIBITED_TAGS.join('|')})\\b`, 'gi');
    if (regex.test(markdown)) {
        return { safe: false, error: "Malicious content detected", sanitized: null };
    }

    // Sanitizar el contenido
    const sanitized = sanitizeHtml(markdown, {
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
        disallowedTagsMode: 'discard' // Esto sigue eliminando las etiquetas
    });

    return { safe: true, sanitized };
};

app.post('/validate', (req, res) => {
    let { markdown } = req.body;

    if (!markdown) {
        return res.status(400).json({ safe: false, error: "No Markdown provided" });
    }

    markdown = String(markdown);
    let frontMatter = markdown.match(/^---\n([\s\S]*?)\n---\n/)?.[0] || '';
    markdown = markdown.replace(/^---\n([\s\S]*?)\n---\n/, '');

    // Validar contenido antes de sanitizar
    const validationResult = validateMarkdown(markdown);
    if (!validationResult.safe) {
        return res.status(400).json({ safe: false, error: "Malicious content detected", sanitized: null });
    }

    let finalMarkdown = frontMatter ? `${frontMatter}\n${validationResult.sanitized}` : validationResult.sanitized;

    res.json({ safe: true, message: "Markdown is safe", sanitized: finalMarkdown });
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Security Service running on port ${PORT}`));
