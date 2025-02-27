const express = require('express');
const sanitizeHtml = require('sanitize-html');

const app = express();
app.use(express.json());

const PROHIBITED_TAGS = ['script', 'iframe', 'object', 'embed', 'form', 'meta', 'link'];

const validateMarkdown = (markdown) => {
    // Sanitizar el contenido antes de verificar seguridad
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
        disallowedTagsMode: 'discard' // Esto elimina las etiquetas no permitidas
    });

    // Determinar si el contenido original ha sido modificado
    const isSafe = markdown.trim() === sanitized.trim();

    return { safe: isSafe, sanitized };
};

app.post('/validate', (req, res) => {
    let { markdown } = req.body;

    if (!markdown) {
        return res.status(400).json({ safe: false, error: "No Markdown provided" });
    }

    markdown = String(markdown);
    let frontMatter = markdown.match(/^---\n([\s\S]*?)\n---\n/)?.[0] || '';
    markdown = markdown.replace(/^---\n([\s\S]*?)\n---\n/, '');

    // Validar contenido después de sanitizar
    const validationResult = validateMarkdown(markdown);

    let finalMarkdown = frontMatter ? `${frontMatter}\n${validationResult.sanitized}` : validationResult.sanitized;

    res.status(200).json({
        safe: validationResult.safe,
        message: validationResult.safe ? "Markdown is safe" : "Markdown contains unsafe content",
        sanitized: finalMarkdown
    });
});


// Solo inicia el servidor si este script es ejecutado directamente
if (require.main === module) {
    const PORT = process.env.PORT || 5001;
    app.listen(PORT, () => {
        console.log(`Servidor escuchando en http://localhost:${PORT}`);
    });
}

module.exports = app; // Exportamos la app para los tests
