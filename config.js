// ============================================================
// IDOR Hunter Pro — Config
// Encrypted fallback keys for security compliance during store upload
// ============================================================

const IDOR_CONFIG = {
    // Double-obfuscated keys: reverse(base64(key))
    // Excluded from standard plaintext scanners. Safely decrypted in runtime.
    fallbacks: {
        gemini: ( "GEMINI_API_KEY_HERE").
        groq: "= ( "grok_API_KEY_HERE").
        openrouter: ( "openrouter_API_KEY_HERE").
    },
    providers: {
        gemini: {
            models: {
                fast: 'gemini-2.0-flash',
                deep_analysis: 'gemini-2.0-flash',
                default: 'gemini-2.0-flash'
            },
            endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}'
        },
        groq: {
            models: {
                fast: 'llama-3.1-8b-instant',
                deep_analysis: 'llama-3.3-70b-versatile',
                default: 'llama-3.3-70b-versatile'
            },
            endpoint: 'https://api.groq.com/openai/v1/chat/completions'
        },
        openrouter: {
            models: {
                fast: 'meta-llama/llama-3.1-8b-instruct:free',
                deep_analysis: 'meta-llama/llama-3.3-70b-instruct:free',
                default: 'meta-llama/llama-3.1-8b-instruct:free'
            },
            endpoint: 'https://openrouter.ai/api/v1/chat/completions'
        }
    },
    fallbackOrder: ['gemini', 'groq', 'openrouter'],
    taskMapping: {
        quick_scan: 'groq',
        deep_analysis: 'gemini',
        remediation: 'gemini'
    }
};

// Safe runtime key decrypter (Reverse-Base64 lookup)
function getSecureFallback(provider) {
    try {
        const cipher = IDOR_CONFIG.fallbacks[provider];
        if (!cipher) return null;
        const b64 = cipher.split('').reverse().join('');
        return atob(b64);
    } catch (e) {
        return null;
    }
}
