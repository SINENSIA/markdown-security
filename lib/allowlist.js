const fs = require('node:fs');

const DEFAULT_ALLOWLIST = Object.freeze({
    allowedTags: Object.freeze([
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'blockquote', 'ul', 'ol', 'li', 'br', 'hr',
        'strong', 'em', 'u', 's', 'b', 'i', 'mark', 'sub', 'sup',
        'pre', 'code', 'kbd', 'samp',
        'table', 'thead', 'tbody', 'tr', 'td', 'th',
        'a', 'img',
        'dl', 'dt', 'dd',
    ]),
    allowedAttributes: Object.freeze({
        a: Object.freeze(['href', 'title', 'target']),
        img: Object.freeze(['src', 'alt', 'width', 'height']),
        code: Object.freeze(['class']),
    }),
    allowedSchemes: Object.freeze(['http', 'https', 'mailto']),
    disallowedTagsMode: 'discard',
});

function loadAllowlist({ path = process.env.ALLOWLIST_FILE } = {}) {
    if (!path) return DEFAULT_ALLOWLIST;

    let raw;
    try {
        raw = fs.readFileSync(path, 'utf8');
    } catch (err) {
        throw new Error(`ALLOWLIST_FILE: cannot read "${path}": ${err.message}`);
    }

    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (err) {
        throw new Error(`ALLOWLIST_FILE: invalid JSON in "${path}": ${err.message}`);
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('ALLOWLIST_FILE: top-level must be a JSON object');
    }
    if (!Array.isArray(parsed.allowedTags)) {
        throw new Error('ALLOWLIST_FILE: "allowedTags" must be an array');
    }
    if (
        parsed.allowedAttributes !== undefined &&
        (typeof parsed.allowedAttributes !== 'object' ||
            Array.isArray(parsed.allowedAttributes) ||
            parsed.allowedAttributes === null)
    ) {
        throw new Error('ALLOWLIST_FILE: "allowedAttributes" must be an object');
    }
    if (parsed.allowedSchemes !== undefined && !Array.isArray(parsed.allowedSchemes)) {
        throw new Error('ALLOWLIST_FILE: "allowedSchemes" must be an array');
    }

    return parsed;
}

module.exports = { DEFAULT_ALLOWLIST, loadAllowlist };
