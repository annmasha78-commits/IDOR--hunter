// ============================================================
// IDOR Hunter Pro v2.2 — Background Service Worker
// Balanced: catches real IDOR signals, filters obvious telemetry
// ============================================================

try {
    importScripts('config.js');
} catch (e) {
    console.error("Failed to import config.js inside service worker:", e);
}

const IDOR_PARAMS = [
    'id', 'user_id', 'uid', 'account_id', 'profile_id', 'doc_id',
    'order_id', 'invoice_id', 'file_id', 'record_id', 'post_id',
    'ticket_id', 'customer_id', 'member_id', 'report_id',
    'transaction_id', 'employee_id', 'resource_id', 'item_id',
    'userid', 'docid', 'fileid', 'objectid', 'entityid'
];

const BUSINESS_PATHS = [
    'user', 'users', 'account', 'accounts', 'profile', 'profiles',
    'invoice', 'invoices', 'order', 'orders', 'ticket', 'tickets',
    'document', 'documents', 'report', 'reports', 'employee', 'employees',
    'customer', 'customers', 'member', 'members', 'record', 'records',
    'file', 'files', 'payment', 'payments', 'transaction', 'subscription',
    'contract', 'project', 'projects', 'task', 'tasks', 'message',
    'messages', 'admin', 'dashboard', 'api'
];

// Only exact telemetry DOMAINS (not broad patterns)
const TELEMETRY_DOMAINS = [
    'newrelic.com', 'nr-data.net',
    'google-analytics.com', 'analytics.google.com', 'googletagmanager.com',
    'hotjar.com', 'mixpanel.com', 'segment.io', 'segment.com',
    'amplitude.com', 'heap.io', 'fullstory.com', 'logrocket.com',
    'datadog.com', 'sentry.io', 'bugsnag.com', 'rollbar.com',
    'pingdom.com', 'doubleclick.net', 'facebook.net',
    'bat.bing.com', 'sc.omtrdc.net'
];

// Telemetry-specific path keywords
const TELEMETRY_PATHS = [
    '/jserrors', '/events/bulk', '/metrics', '/beacon',
    '/collect', '/rum/', '/apm/', '/healthcheck', '/health/ping'
];

function isTelemetry(url) {
    try {
        const u = new URL(url);
        const host = u.hostname.toLowerCase();
        const path = u.pathname.toLowerCase();

        // Exact domain match
        if (TELEMETRY_DOMAINS.some(d => host === d || host.endsWith('.' + d))) return true;

        // Path-specific telemetry patterns (very specific)
        if (TELEMETRY_PATHS.some(p => path.startsWith(p))) return true;

        return false;
    } catch (e) {
        return false;
    }
}

function classifyEndpoint(url, method, type) {
    try {
        const u = new URL(url);
        const path = u.pathname.toLowerCase();
        const pathSegs = u.pathname.split('/').filter(Boolean);

        // Filter obvious telemetry
        if (isTelemetry(url)) {
            return { hasPotential: false, category: 'telemetry', findings: [], score: 0, reason: '' };
        }

        let score = 0;
        let findings = [];
        let reasonParts = [];

        // API/XHR requests get bonus
        if (type === 'xmlhttprequest') score += 15;

        // --- Query Parameters ---
        for (const [key, value] of u.searchParams.entries()) {
            const keyLower = key.toLowerCase();

            // Named IDOR params
            if (IDOR_PARAMS.some(p => keyLower === p || keyLower.includes(p))) {
                score += 40;
                findings.push({ type: 'query_idor', key, value, label: `?${key}=${value}` });
                reasonParts.push(`IDOR-sensitive parameter "${key}=${value}" in query string`);
            }
            // Any numeric value in a param
            else if (!isNaN(value) && value.trim() !== '' && parseInt(value) > 0) {
                score += 20;
                findings.push({ type: 'query_numeric', key, value, label: `?${key}=${value}` });
                reasonParts.push(`Numeric value "${value}" in query parameter "${key}"`);
            }
        }

        // --- Path Segments ---
        let businessContext = false;
        pathSegs.forEach((seg, i) => {
            const segLower = seg.toLowerCase();

            // Track business context
            if (BUSINESS_PATHS.includes(segLower)) {
                businessContext = true;
            }

            // Numeric ID in path
            if (/^\d+$/.test(seg) && parseInt(seg) > 0) {
                const pts = businessContext ? 40 : 22;
                score += pts;
                findings.push({ type: 'path_id', key: `path[${i}]`, value: seg, label: `/${seg}` });
                if (businessContext) {
                    reasonParts.push(`Numeric object ID "${seg}" in business resource path`);
                } else {
                    reasonParts.push(`Numeric ID "${seg}" detected in URL path segment`);
                }
            }

            // UUID in path
            if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) {
                score += 28;
                findings.push({ type: 'path_uuid', key: `uuid[${i}]`, value: seg.substring(0, 8) + '...', label: `/UUID` });
                reasonParts.push(`UUID identifier in URL path — may reference a specific resource`);
            }
        });

        // Bonus for API + business path + numeric
        if (path.includes('/api/') && businessContext) score += 15;

        if (findings.length === 0) {
            return { hasPotential: false, category: 'info', findings: [], score: 0, reason: '' };
        }

        const reason = reasonParts[0] || 'Numeric identifier detected in URL';

        // --- Classify ---
        let category;
        if (score >= 65) category = 'high';
        else if (score >= 40) category = 'medium';
        else if (score >= 20) category = 'low';
        else category = 'info';

        return { hasPotential: true, category, findings, score, reason };

    } catch (e) {
        return { hasPotential: false };
    }
}

function saveFinding(finding) {
    chrome.storage.local.get({ idorFindings: [] }, result => {
        let findings = result.idorFindings;
        if (!findings.some(f => f.url === finding.url)) {
            findings.unshift(finding);
            if (findings.length > 150) findings.pop();
            chrome.storage.local.set({ idorFindings: findings });
        }
    });
}

chrome.webRequest.onCompleted.addListener(details => {
    // Focus on XHR (API calls) and sub-frames
    if (details.type !== 'xmlhttprequest' && details.type !== 'sub_frame') return;

    const result = classifyEndpoint(details.url, details.method, details.type);

    if (result && result.hasPotential) {
        saveFinding({
            url: details.url,
            method: details.method,
            category: result.category,
            score: result.score,
            findings: result.findings,
            reason: result.reason,
            status: details.statusCode,
            timestamp: new Date().toISOString(),
            verified: false,
            verificationResult: null
        });
    }
}, { urls: ['<all_urls>'] });
