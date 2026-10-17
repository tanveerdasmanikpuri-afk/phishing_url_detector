// test_heuristics.js
// Automated verification for the Phishing URL Detector logic

// 1. Levenshtein Distance (DP matrix implementation per spec)
function levenshteinDistance(s1, s2) {
    const m = s1.length;
    const n = s2.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            if (s1[i - 1] === s2[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + Math.min(
                    dp[i - 1][j],     // deletion
                    dp[i][j - 1],     // insertion
                    dp[i - 1][j - 1]  // substitution
                );
            }
        }
    }
    return dp[m][n];
}

// Brand list for typosquatting (~19 major brands)
const BRAND_TARGETS = [
    'paypal', 'google', 'apple', 'amazon', 'microsoft',
    'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
    'github', 'dropbox', 'yahoo', 'adobe', 'spotify',
    'ebay', 'whatsapp', 'binance', 'chase'
];

// Risky TLDs
const RISKY_TLDS = new Set([
    'tk', 'xyz', 'click', 'top', 'work', 'loan', 'gq', 'cf', 'ga', 'ml',
    'buzz', 'fit', 'country', 'surf', 'racing', 'link', 'rest', 'mom',
    'icu', 'cam'
]);

// Suspicious keywords
const PHISH_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'banking',
    'signin', 'confirm', 'password', 'credential', 'support',
    'billing', 'authenticate', 'wallet', 'recover'
];

// Known URL shorteners
const SHORTENERS = new Set([
    'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly',
    'goo.gl', 'rebrand.ly', 'cutt.ly', 'bitly.com', 'tiny.cc'
]);

// Main analysis function
function analyzeUrl(rawInput) {
    const raw = (rawInput || '').trim();
    if (!raw) {
        return { error: 'Please enter a URL to analyze.' };
    }

    // Step 1: Parsing the input
    let urlString = raw;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlString)) {
        urlString = 'http://' + urlString;
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(urlString);
    } catch (e) {
        return { error: 'Not a valid URL. Please check the format.' };
    }

    // Step 2: Extracting pieces needed
    const host = parsedUrl.hostname.toLowerCase();
    const parts = host.split('.').filter(Boolean);
    const tld = parts.length > 0 ? parts[parts.length - 1] : '';
    const domainCore = parts.length >= 2 ? parts[parts.length - 2] : (parts[0] || host);

    let score = 0;
    const findings = [];

    // Check 1: Raw IP host (+25)
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(host)) {
        score += 25;
        findings.push({
            name: 'Raw IP Host',
            severity: 'danger',
            tag: 'FLAG',
            points: 25,
            message: `Domain is a raw IP address (${host}) instead of a standard hostname, commonly used in phishing attacks.`
        });
    }

    // Check 2: @ symbol (+20)
    if (raw.includes('@')) {
        score += 20;
        findings.push({
            name: '@ Symbol Present',
            severity: 'danger',
            tag: 'FLAG',
            points: 20,
            message: 'Contains "@" symbol. Browsers ignore everything prior to the "@" sign, often disguising destination hosts.'
        });
    }

    // Check 3: Punycode (+20)
    if (host.includes('xn--')) {
        score += 20;
        findings.push({
            name: 'Punycode Host',
            severity: 'danger',
            tag: 'FLAG',
            points: 20,
            message: 'Contains Punycode ("xn--"), indicating encoded international lookalike characters commonly used in homograph attacks.'
        });
    }

    // Check 4: Typosquatting (+28)
    let typosquatMatch = null;
    let minDistance = Infinity;
    const coreClean = domainCore.toLowerCase();
    const candidates = [coreClean, ...coreClean.split('-').filter(t => t.length >= 3)];

    for (const cand of candidates) {
        for (const brand of BRAND_TARGETS) {
            const dist = levenshteinDistance(cand, brand);
            if (dist > 0 && dist <= 2) {
                if (dist < minDistance) {
                    minDistance = dist;
                    typosquatMatch = { brand, dist, token: cand };
                }
            }
        }
    }
    if (typosquatMatch) {
        score += 28;
        findings.push({
            name: 'Typosquatting Detected',
            severity: 'danger',
            tag: 'FLAG',
            points: 28,
            message: `Domain segment "${domainCore}" is an edit distance of ${typosquatMatch.dist} from major brand "${typosquatMatch.brand}".`
        });
    }

    // Check 5: Risky TLD (+12)
    if (RISKY_TLDS.has(tld)) {
        score += 12;
        findings.push({
            name: 'Risky Top-Level Domain',
            severity: 'warn',
            tag: 'FLAG',
            points: 12,
            message: `TLD ".${tld}" belongs to an extension registry disproportionately associated with abuse and phishing campaigns.`
        });
    }

    // Check 6: Keyword stuffing (+5 or +14)
    const rawLower = raw.toLowerCase();
    let keywordHits = 0;
    const detectedKeywords = [];
    for (const kw of PHISH_KEYWORDS) {
        if (rawLower.includes(kw)) {
            keywordHits++;
            detectedKeywords.push(kw);
        }
    }
    if (keywordHits >= 2) {
        score += 14;
        findings.push({
            name: 'Multiple Security Keywords',
            severity: 'warn',
            tag: 'FLAG',
            points: 14,
            message: `Contains multiple security/credential keywords (${detectedKeywords.slice(0, 4).join(', ')}). Phishers frequently stack these words to create a false sense of urgency.`
        });
    } else if (keywordHits === 1) {
        score += 5;
        findings.push({
            name: 'Suspicious Keyword',
            severity: 'warn',
            tag: 'FLAG',
            points: 5,
            message: `Contains sensitive security keyword "${detectedKeywords[0]}".`
        });
    }

    // Check 7: Shortener (+15)
    if (SHORTENERS.has(host)) {
        score += 15;
        findings.push({
            name: 'URL Shortener',
            severity: 'warn',
            tag: 'NOTE',
            points: 15,
            message: `Domain "${host}" is a known URL shortening service, which conceals the actual target destination.`
        });
    }

    // Check 8: Excess subdomains (+10)
    if (parts.length > 3) {
        score += 10;
        findings.push({
            name: 'Excess Subdomains',
            severity: 'warn',
            tag: 'NOTE',
            points: 10,
            message: `Host has ${parts.length} segments (${parts.length - 2} subdomains), often used to simulate complex corporate structures or disguise the root domain.`
        });
    }

    // Check 9: Multiple hyphens (+10)
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
        score += 10;
        findings.push({
            name: 'Multiple Hyphens',
            severity: 'warn',
            tag: 'NOTE',
            points: 10,
            message: `Host contains ${hyphenCount} hyphens. Deceptive domains frequently link brand names with fake services via hyphens.`
        });
    }

    // Check 10: No HTTPS (+10)
    if (parsedUrl.protocol !== 'https:') {
        score += 10;
        findings.push({
            name: 'Unencrypted Protocol (No HTTPS)',
            severity: 'warn',
            tag: 'NOTE',
            points: 10,
            message: `Protocol is "${parsedUrl.protocol.replace(':', '')}". Lack of HTTPS means communication is unencrypted and lacks valid SSL identity validation.`
        });
    }

    // Check 11: Long URL (+8)
    if (raw.length > 75) {
        score += 8;
        findings.push({
            name: 'Excessive URL Length',
            severity: 'info',
            tag: 'INFO',
            points: 8,
            message: `URL length is ${raw.length} characters (exceeds 75). Abnormally long URLs are commonly used to push suspicious domain names out of visible address bars.`
        });
    }

    // Check 12: Special characters (+6)
    const specialMatch = raw.match(/[%$!*]/g) || [];
    if (specialMatch.length >= 3) {
        score += 6;
        findings.push({
            name: 'Multiple Special Characters',
            severity: 'warn',
            tag: 'NOTE',
            points: 6,
            message: `Contains ${specialMatch.length} special characters (%, $, !, *), often indicating obfuscation or complex tracking tokens.`
        });
    }

    // Step 5: Totaling the score
    const finalScore = Math.min(score, 100);

    // Step 6: Assigning a verdict
    let verdict = '';
    let verdictClass = '';
    if (finalScore >= 50) {
        verdict = 'HIGH RISK';
        verdictClass = 'danger';
    } else if (finalScore >= 20) {
        verdict = 'SUSPICIOUS';
        verdictClass = 'warn';
    } else {
        verdict = 'LOW RISK';
        verdictClass = 'safe';
    }

    // Default note if nothing triggered
    if (findings.length === 0) {
        findings.push({
            name: 'Clean Domain Analysis',
            severity: 'safe',
            tag: 'CLEAR',
            points: 0,
            message: 'No suspicious phishing patterns detected for this URL.'
        });
    }

    return {
        raw,
        parsedUrl: {
            href: parsedUrl.href,
            protocol: parsedUrl.protocol,
            host,
            parts,
            tld,
            domainCore
        },
        score: finalScore,
        rawScore: score,
        verdict,
        verdictClass,
        findings
    };
}

// -------------------------------------------------------------
// Unit Test Suite
// -------------------------------------------------------------
function runTests() {
    console.log('=== RUNNING PHISHING URL DETECTOR TESTS ===\n');
    let passed = 0;
    let failed = 0;

    function assert(condition, testName, details = '') {
        if (condition) {
            console.log(`[PASS] ${testName}`);
            passed++;
        } else {
            console.error(`[FAIL] ${testName} - ${details}`);
            failed++;
        }
    }

    // 1. Levenshtein test
    assert(levenshteinDistance('paypa1', 'paypal') === 1, 'Levenshtein: paypa1 -> paypal distance 1');
    assert(levenshteinDistance('g00gle', 'google') === 2, 'Levenshtein: g00gle -> google distance 2');
    assert(levenshteinDistance('google', 'google') === 0, 'Levenshtein: identical strings distance 0');
    assert(levenshteinDistance('microsoft', 'micros0ft') === 1, 'Levenshtein: micros0ft -> microsoft distance 1');

    // 2. Typosquat check trigger
    const typosquatRes = analyzeUrl('http://paypa1-security.com');
    const hasTyposquat = typosquatRes.findings.some(f => f.name === 'Typosquatting Detected');
    assert(hasTyposquat, 'Detects typosquatting on paypa1');

    // 3. Raw IP check
    const ipRes = analyzeUrl('http://192.168.1.1/login');
    const hasIp = ipRes.findings.some(f => f.name === 'Raw IP Host');
    assert(hasIp, 'Detects Raw IP host');

    // 4. @ symbol check
    const atRes = analyzeUrl('https://legit.com@phishing.com');
    const hasAt = atRes.findings.some(f => f.name === '@ Symbol Present');
    assert(hasAt, 'Detects @ symbol in URL');

    // 5. Punycode check
    const punyRes = analyzeUrl('https://xn--pple-43d.com');
    const hasPuny = punyRes.findings.some(f => f.name === 'Punycode Host');
    assert(hasPuny, 'Detects Punycode xn-- host');

    // 6. Risky TLD check
    const tldRes = analyzeUrl('http://secure-banking.tk');
    const hasTld = tldRes.findings.some(f => f.name === 'Risky Top-Level Domain');
    assert(hasTld, 'Detects risky TLD .tk');

    // 7. Keyword stuffing check
    const kwRes = analyzeUrl('http://bank.com/login/verify/account/password');
    const hasKw = kwRes.findings.some(f => f.name === 'Multiple Security Keywords' && f.points === 14);
    assert(hasKw, 'Detects multiple security keywords (+14 points)');

    // 8. Shortener check
    const shortRes = analyzeUrl('https://bit.ly/3xXyZ');
    const hasShort = shortRes.findings.some(f => f.name === 'URL Shortener');
    assert(hasShort, 'Detects bit.ly URL shortener');

    // 9. Excess subdomains
    const subRes = analyzeUrl('https://a.b.c.example.com');
    const hasSub = subRes.findings.some(f => f.name === 'Excess Subdomains');
    assert(hasSub, 'Detects excess subdomains (> 3 parts)');

    // 10. Multiple hyphens
    const hyphenRes = analyzeUrl('https://my-secure-login-portal.com');
    const hasHyphen = hyphenRes.findings.some(f => f.name === 'Multiple Hyphens');
    assert(hasHyphen, 'Detects multiple hyphens (2+)');

    // 11. No HTTPS check
    const httpRes = analyzeUrl('http://example.com');
    const hasNoHttps = httpRes.findings.some(f => f.name === 'Unencrypted Protocol (No HTTPS)');
    assert(hasNoHttps, 'Detects unencrypted HTTP protocol');

    // 12. Long URL check
    const longUrl = 'https://example.com/' + 'a'.repeat(70);
    const longRes = analyzeUrl(longUrl);
    const hasLong = longRes.findings.some(f => f.name === 'Excessive URL Length');
    assert(hasLong, 'Detects URL > 75 chars');

    // 13. Special characters check
    const specRes = analyzeUrl('https://example.com/test?a=%20&b=$10&c=!*');
    const hasSpec = specRes.findings.some(f => f.name === 'Multiple Special Characters');
    assert(hasSpec, 'Detects 3+ special characters');

    // 14. Verdict checks
    const safeRes = analyzeUrl('https://google.com');
    assert(safeRes.score < 20 && safeRes.verdict === 'LOW RISK', 'google.com is LOW RISK (<20)');

    const highRiskUrl = 'http://paypa1-security.tk/login/verify?user=test';
    const highRiskRes = analyzeUrl(highRiskUrl);
    assert(highRiskRes.score >= 50 && highRiskRes.verdict === 'HIGH RISK', 'paypa1 on .tk is HIGH RISK (>=50)');

    const cleanRes = analyzeUrl('https://wikipedia.org/wiki/Computer');
    assert(cleanRes.findings.some(f => f.tag === 'CLEAR'), 'Clean site includes CLEAR note when 0 triggers');

    // 15. Invalid URL check
    const invalidRes = analyzeUrl('://bad url');
    assert(invalidRes.error !== undefined, 'Reports invalid URL error correctly');

    console.log(`\nTests completed: ${passed} passed, ${failed} failed.`);
    if (failed > 0) process.exit(1);
}

if (typeof module !== 'undefined' && require.main === module) {
    runTests();
}

if (typeof module !== 'undefined') {
    module.exports = { levenshteinDistance, analyzeUrl };
}
