/**
 * Phishing URL Detector
 * 100% Client-side Heuristic Engine & Levenshtein Distance Matrix
 * Zero network calls - complete privacy
 */

// 1. Brand list for Typosquatting (~19 major brands)
const BRAND_TARGETS = [
    'paypal', 'google', 'apple', 'amazon', 'microsoft',
    'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
    'github', 'dropbox', 'yahoo', 'adobe', 'spotify',
    'ebay', 'whatsapp', 'binance', 'chase'
];

// Risky TLDs frequently abused in phishing campaigns
const RISKY_TLDS = new Set([
    'tk', 'xyz', 'click', 'top', 'work', 'loan', 'gq', 'cf', 'ga', 'ml',
    'buzz', 'fit', 'country', 'surf', 'racing', 'link', 'rest', 'mom',
    'icu', 'cam'
]);

// Security / credential keywords
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

/**
 * Levenshtein Distance (Classic Dynamic-Programming Matrix)
 * Builds an (m+1) x (n+1) grid:
 * - First row/col filled with 0, 1, 2, 3...
 * - For each cell: diagonal if chars match, or 1 + min(left, up, diagonal)
 * - Returns bottom-right cell value
 */
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
                    dp[i - 1][j],      // Deletion (left)
                    dp[i][j - 1],      // Insertion (up)
                    dp[i - 1][j - 1]   // Substitution (diagonal)
                );
            }
        }
    }
    return dp[m][n];
}

/**
 * Main URL Inspection Engine
 * Executes 12 heuristic checks strictly per specification
 */
function inspectUrl(rawInput) {
    const raw = (rawInput || '').trim();
    if (!raw) {
        return { error: 'Please enter a URL to inspect.' };
    }

    // Step 1: Parsing the input
    let urlString = raw;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlString)) {
        urlString = 'http://' + urlString;
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(urlString);
        // Verify hostname exists (e.g. "http://" alone is invalid)
        if (!parsedUrl.hostname || parsedUrl.hostname.trim() === '') {
            throw new Error('Missing hostname');
        }
    } catch (err) {
        return { error: 'Not a valid URL. Please check the format and try again.' };
    }

    // Step 2: Extracting the pieces it needs
    const host = parsedUrl.hostname.toLowerCase();
    const parts = host.split('.').filter(Boolean);
    const tld = parts.length > 0 ? parts[parts.length - 1] : '';
    // domainCore: second-to-last part ("brand-looking" segment)
    const domainCore = parts.length >= 2 ? parts[parts.length - 2] : (parts[0] || host);

    let score = 0;
    const findings = [];

    // Check 1: Raw IP host (+25)
    // Regex tests if hostname is 4 dot-separated numbers
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(host)) {
        score += 25;
        findings.push({
            name: 'Raw IP Host',
            severity: 'danger',
            tag: 'FLAG',
            points: 25,
            message: `Domain is a raw IP address (${host}) instead of a registered domain name. Legitimate web services rarely direct users directly to numerical IPs.`
        });
    }

    // Check 2: @ symbol (+20)
    // raw.includes('@') — browsers discard everything before @
    if (raw.includes('@')) {
        score += 20;
        findings.push({
            name: '@ Symbol Obfuscation',
            severity: 'danger',
            tag: 'FLAG',
            points: 20,
            message: 'Contains "@" symbol. Standard web browsers discard all characters prior to the "@" symbol, masking the true destination host.'
        });
    }

    // Check 3: Punycode (+20)
    // host.includes('xn--') — flags encoded lookalike-character domains
    if (host.includes('xn--')) {
        score += 20;
        findings.push({
            name: 'Punycode Homograph',
            severity: 'danger',
            tag: 'FLAG',
            points: 20,
            message: 'Host utilizes Punycode encoding ("xn--"). Attackers frequently use this technique with Cyrillic or Greek lookalike characters to mimic legitimate brands.'
        });
    }

    // Check 4: Typosquatting (+28)
    // Levenshtein distance between domainCore and ~19 major brand names; distance <= 2 and not an exact match
    let closestBrand = null;
    let minDistance = Infinity;
    let matchedToken = '';
    const coreClean = domainCore.toLowerCase();
    const candidates = [coreClean, ...coreClean.split('-').filter(t => t.length >= 3)];

    for (const cand of candidates) {
        for (const brand of BRAND_TARGETS) {
            const dist = levenshteinDistance(cand, brand);
            if (dist > 0 && dist <= 2) {
                if (dist < minDistance) {
                    minDistance = dist;
                    closestBrand = brand;
                    matchedToken = cand;
                }
            }
        }
    }

    if (closestBrand) {
        score += 28;
        const targetLabel = matchedToken === coreClean ? `"${domainCore}"` : `segment "${matchedToken}" in "${domainCore}"`;
        findings.push({
            name: 'Typosquatting Detected',
            severity: 'danger',
            tag: 'FLAG',
            points: 28,
            message: `Domain ${targetLabel} has an edit distance of ${minDistance} from well-known brand "${closestBrand}". High likelihood of visual brand imitation.`
        });
    }

    // Check 5: Risky TLD (+12)
    // tld is in a list of extensions disproportionately used in phishing (.tk, .xyz, .click...)
    if (RISKY_TLDS.has(tld)) {
        score += 12;
        findings.push({
            name: 'High-Abuse TLD',
            severity: 'warn',
            tag: 'FLAG',
            points: 12,
            message: `The top-level domain ".${tld}" has a statistically high rate of malicious registration and phishing activity.`
        });
    }

    // Check 6: Keyword stuffing (+5 or +14)
    // Counts hits from list (login, verify, secure...) in full URL string
    const rawLower = raw.toLowerCase();
    const matchedKeywords = [];
    for (const kw of PHISH_KEYWORDS) {
        if (rawLower.includes(kw)) {
            matchedKeywords.push(kw);
        }
    }

    if (matchedKeywords.length >= 2) {
        score += 14;
        findings.push({
            name: 'Multiple Phishing Keywords',
            severity: 'warn',
            tag: 'FLAG',
            points: 14,
            message: `Detected multiple credential & security keywords (${matchedKeywords.slice(0, 4).join(', ')}). Phishing sites frequently stack deceptive keywords.`
        });
    } else if (matchedKeywords.length === 1) {
        score += 5;
        findings.push({
            name: 'Sensitive Keyword Present',
            severity: 'warn',
            tag: 'FLAG',
            points: 5,
            message: `URL contains sensitive action keyword "${matchedKeywords[0]}".`
        });
    }

    // Check 7: Shortener (+15)
    // host matches a known shortener list (bit.ly, t.co...)
    if (SHORTENERS.has(host)) {
        score += 15;
        findings.push({
            name: 'URL Shortening Service',
            severity: 'warn',
            tag: 'NOTE',
            points: 15,
            message: `Host "${host}" is a URL shortener that conceals the true landing page and redirects the user.`
        });
    }

    // Check 8: Excess subdomains (+10)
    // parts.length > 3
    if (parts.length > 3) {
        score += 10;
        findings.push({
            name: 'Excessive Subdomains',
            severity: 'warn',
            tag: 'NOTE',
            points: 10,
            message: `Domain has ${parts.length} segments (${parts.length - 2} subdomains). Complex multi-level subdomains are commonly engineered to mislead users.`
        });
    }

    // Check 9: Multiple hyphens (+10)
    // 2+ - characters in the host
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
        score += 10;
        findings.push({
            name: 'Multiple Hyphens in Host',
            severity: 'warn',
            tag: 'NOTE',
            points: 10,
            message: `Host domain contains ${hyphenCount} hyphens. Deceptive campaigns frequently chain hyphens to stitch legitimate brand names with fake words.`
        });
    }

    // Check 10: No HTTPS (+10)
    // url.protocol !== 'https:'
    if (parsedUrl.protocol !== 'https:') {
        score += 10;
        findings.push({
            name: 'Unencrypted Connection (No HTTPS)',
            severity: 'warn',
            tag: 'NOTE',
            points: 10,
            message: `Uses unencrypted ${parsedUrl.protocol.replace(':', '').toUpperCase()} protocol instead of HTTPS. Traffic lacks encryption and authenticated SSL/TLS identity.`
        });
    }

    // Check 11: Long URL (+8)
    // raw.length > 75
    if (raw.length > 75) {
        score += 8;
        findings.push({
            name: 'Excessive URL Length',
            severity: 'info',
            tag: 'INFO',
            points: 8,
            message: `URL length is ${raw.length} characters (> 75 chars). Unusually long URLs are often used to hide the true target domain on mobile displays.`
        });
    }

    // Check 12: Special chars (+6)
    // 3+ of % $ ! * in the raw string
    const specialChars = raw.match(/[%$!*]/g) || [];
    if (specialChars.length >= 3) {
        score += 6;
        findings.push({
            name: 'Special Characters Obfuscation',
            severity: 'warn',
            tag: 'NOTE',
            points: 6,
            message: `Contains ${specialChars.length} suspicious special symbols (%, $, !, *), often indicating character encoding or parameter obfuscation.`
        });
    }

    // Step 5: Totaling the score (capped at 100)
    const finalScore = Math.min(score, 100);

    // Step 6: Assigning a verdict
    // >= 50 -> HIGH RISK (red stamp)
    // 20-49 -> SUSPICIOUS (amber stamp)
    // < 20 -> LOW RISK (green stamp)
    let verdict = '';
    let verdictClass = '';
    let verdictDesc = '';

    if (finalScore >= 50) {
        verdict = 'HIGH RISK';
        verdictClass = 'verdict-danger';
        verdictDesc = 'Multiple high-confidence phishing indicators detected. Avoid visiting or submitting credentials to this link.';
    } else if (finalScore >= 20) {
        verdict = 'SUSPICIOUS';
        verdictClass = 'verdict-warn';
        verdictDesc = 'Anomalous or suspicious patterns observed. Proceed with extreme caution and verify the source.';
    } else {
        verdict = 'LOW RISK';
        verdictClass = 'verdict-safe';
        verdictDesc = 'Standard URL structure. No obvious phishing or typosquatting indicators found.';
    }

    // If nothing triggered at all, add a single "no patterns detected" note so results list is never empty
    if (findings.length === 0) {
        findings.push({
            name: 'Clean Heuristic Profile',
            severity: 'safe',
            tag: 'CLEAR',
            points: 0,
            message: 'No suspicious phishing patterns detected for this URL. Domain structure and protocol appear standard.'
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
            domainCore,
            pathname: parsedUrl.pathname,
            search: parsedUrl.search
        },
        score: finalScore,
        rawScore: score,
        verdict,
        verdictClass,
        verdictDesc,
        findings
    };
}

// -------------------------------------------------------------
// UI Rendering & Event Handling
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const clearBtn = document.getElementById('clear-btn');
    const errorAlert = document.getElementById('error-alert');
    const errorMsg = document.getElementById('error-msg');
    const resultsContainer = document.getElementById('results-container');

    // Result elements
    const verdictStamp = document.getElementById('verdict-stamp');
    const verdictDesc = document.getElementById('verdict-desc');
    const scoreNumber = document.getElementById('score-number');
    const scoreBarFill = document.getElementById('score-bar-fill');
    const findingsList = document.getElementById('findings-list');

    // URL Breakdown chips
    const chipProtocol = document.getElementById('chip-protocol');
    const chipHost = document.getElementById('chip-host');
    const chipCore = document.getElementById('chip-core');
    const chipTld = document.getElementById('chip-tld');
    const chipLength = document.getElementById('chip-length');

    // Quick sample click handlers
    document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleUrl = btn.getAttribute('data-url');
            if (sampleUrl) {
                urlInput.value = sampleUrl;
                runAnalysis();
            }
        });
    });

    // Form submit / button click
    analyzeBtn.addEventListener('click', runAnalysis);
    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            runAnalysis();
        }
    });

    // Clear input
    clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        hideError();
        resultsContainer.classList.add('hidden');
        urlInput.focus();
    });

    function showError(msg) {
        errorMsg.textContent = msg;
        errorAlert.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
    }

    function hideError() {
        errorAlert.classList.add('hidden');
    }

    function runAnalysis() {
        hideError();
        const inputVal = urlInput.value;
        const result = inspectUrl(inputVal);

        if (result.error) {
            showError(result.error);
            return;
        }

        renderResults(result);
    }

    function renderResults(res) {
        // 1. URL Component Chips
        chipProtocol.textContent = res.parsedUrl.protocol;
        chipHost.textContent = res.parsedUrl.host;
        chipCore.textContent = res.parsedUrl.domainCore;
        chipTld.textContent = res.parsedUrl.tld ? '.' + res.parsedUrl.tld : 'None';
        chipLength.textContent = `${res.raw.length} chars`;

        // 2. Verdict Stamp
        verdictStamp.textContent = res.verdict;
        verdictStamp.className = `verdict-stamp ${res.verdictClass}`;
        verdictDesc.textContent = res.verdictDesc;

        // 3. Animated Score Bar & Counter
        scoreNumber.textContent = res.score;
        scoreBarFill.style.width = `${res.score}%`;

        // Color coding for score bar
        scoreBarFill.className = 'score-bar-fill';
        if (res.score >= 50) {
            scoreBarFill.classList.add('fill-danger');
        } else if (res.score >= 20) {
            scoreBarFill.classList.add('fill-warn');
        } else {
            scoreBarFill.classList.add('fill-safe');
        }

        // 4. Rebuild Findings List
        findingsList.innerHTML = '';
        res.findings.forEach(finding => {
            const li = document.createElement('li');
            li.className = `finding-item finding-${finding.severity}`;

            // Tag badge
            const tagSpan = document.createElement('span');
            tagSpan.className = `badge-tag badge-${finding.tag.toLowerCase()}`;
            tagSpan.textContent = finding.tag;

            // Content container
            const contentDiv = document.createElement('div');
            contentDiv.className = 'finding-content';

            const headerDiv = document.createElement('div');
            headerDiv.className = 'finding-header';

            const titleSpan = document.createElement('span');
            titleSpan.className = 'finding-title';
            titleSpan.textContent = finding.name;

            const ptsSpan = document.createElement('span');
            ptsSpan.className = 'finding-points';
            ptsSpan.textContent = finding.points > 0 ? `+${finding.points} pts` : '0 pts';

            headerDiv.appendChild(titleSpan);
            headerDiv.appendChild(ptsSpan);

            const msgP = document.createElement('p');
            msgP.className = 'finding-desc';
            msgP.textContent = finding.message;

            contentDiv.appendChild(headerDiv);
            contentDiv.appendChild(msgP);

            li.appendChild(tagSpan);
            li.appendChild(contentDiv);

            findingsList.appendChild(li);
        });

        // Reveal results container smoothly
        resultsContainer.classList.remove('hidden');
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
});
