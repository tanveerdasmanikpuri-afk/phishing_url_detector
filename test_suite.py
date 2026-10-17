"""
Comprehensive verification test suite for Phishing URL Detector
Tests Levenshtein Distance Matrix and Heuristic Logic matching app.js
"""
import urllib.parse
import re

BRAND_TARGETS = [
    'paypal', 'google', 'apple', 'amazon', 'microsoft',
    'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
    'github', 'dropbox', 'yahoo', 'adobe', 'spotify',
    'ebay', 'whatsapp', 'binance', 'chase'
]

RISKY_TLDS = {
    'tk', 'xyz', 'click', 'top', 'work', 'loan', 'gq', 'cf', 'ga', 'ml',
    'buzz', 'fit', 'country', 'surf', 'racing', 'link', 'rest', 'mom',
    'icu', 'cam'
}

PHISH_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'banking',
    'signin', 'confirm', 'password', 'credential', 'support',
    'billing', 'authenticate', 'wallet', 'recover'
]

SHORTENERS = {
    'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly',
    'goo.gl', 'rebrand.ly', 'cutt.ly', 'bitly.com', 'tiny.cc'
}

def levenshtein_distance(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    return dp[m][n]

def inspect_url(raw_input: str):
    raw = (raw_input or '').strip()
    if not raw:
        return {'error': 'Please enter a URL to inspect.'}

    # Step 1: Parsing
    url_string = raw
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_string):
        url_string = 'http://' + url_string

    try:
        parsed = urllib.parse.urlparse(url_string)
        host = parsed.hostname
        if not host:
            return {'error': 'Not a valid URL. Please check the format and try again.'}
        host = host.lower()
    except Exception:
        return {'error': 'Not a valid URL. Please check the format and try again.'}

    # Step 2: Extraction
    parts = [p for p in host.split('.') if p]
    tld = parts[-1] if parts else ''
    domain_core = parts[-2] if len(parts) >= 2 else (parts[0] if parts else host)

    score = 0
    findings = []

    # Check 1: Raw IP host (+25)
    ipv4_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_regex.match(host):
        score += 25
        findings.append(('Raw IP Host', 25, 'FLAG', 'danger'))

    # Check 2: @ symbol (+20)
    if '@' in raw:
        score += 20
        findings.append(('@ Symbol Present', 20, 'FLAG', 'danger'))

    # Check 3: Punycode (+20)
    if 'xn--' in host:
        score += 20
        findings.append(('Punycode Host', 20, 'FLAG', 'danger'))

    # Check 4: Typosquatting (+28)
    closest_brand = None
    min_dist = float('inf')
    core_clean = domain_core.lower()
    # Check domain_core itself as well as hyphen-separated segments (e.g. paypa1 in paypa1-security)
    candidates = [core_clean] + [seg for seg in core_clean.split('-') if len(seg) >= 3]
    
    for cand in candidates:
        for b in BRAND_TARGETS:
            d = levenshtein_distance(cand, b)
            if 0 < d <= 2 and d < min_dist:
                min_dist = d
                closest_brand = (b, cand)
                
    if closest_brand:
        score += 28
        findings.append((f'Typosquatting Detected ({closest_brand[0]})', 28, 'FLAG', 'danger'))

    # Check 5: Risky TLD (+12)
    if tld in RISKY_TLDS:
        score += 12
        findings.append(('Risky TLD', 12, 'FLAG', 'warn'))

    # Check 6: Keyword stuffing (+5 or +14)
    raw_lower = raw.lower()
    kw_hits = [kw for kw in PHISH_KEYWORDS if kw in raw_lower]
    if len(kw_hits) >= 2:
        score += 14
        findings.append(('Multiple Security Keywords', 14, 'FLAG', 'warn'))
    elif len(kw_hits) == 1:
        score += 5
        findings.append(('Security Keyword', 5, 'FLAG', 'warn'))

    # Check 7: Shortener (+15)
    if host in SHORTENERS:
        score += 15
        findings.append(('URL Shortener', 15, 'NOTE', 'warn'))

    # Check 8: Excess subdomains (+10)
    if len(parts) > 3:
        score += 10
        findings.append(('Excess Subdomains', 10, 'NOTE', 'warn'))

    # Check 9: Multiple hyphens (+10)
    if host.count('-') >= 2:
        score += 10
        findings.append(('Multiple Hyphens', 10, 'NOTE', 'warn'))

    # Check 10: No HTTPS (+10)
    protocol = parsed.scheme.lower()
    if protocol != 'https':
        score += 10
        findings.append(('No HTTPS', 10, 'NOTE', 'warn'))

    # Check 11: Long URL (+8)
    if len(raw) > 75:
        score += 8
        findings.append(('Long URL', 8, 'INFO', 'info'))

    # Check 12: Special chars (+6)
    specials = [c for c in raw if c in '%$!*']
    if len(specials) >= 3:
        score += 6
        findings.append(('Special Characters', 6, 'NOTE', 'warn'))

    final_score = min(score, 100)

    if final_score >= 50:
        verdict = 'HIGH RISK'
    elif final_score >= 20:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'LOW RISK'

    if not findings:
        findings.append(('No patterns detected', 0, 'CLEAR', 'safe'))

    return {
        'host': host,
        'domain_core': domain_core,
        'tld': tld,
        'score': final_score,
        'raw_score': score,
        'verdict': verdict,
        'findings': findings
    }

def run_tests():
    print("========================================")
    print("PHISHING DETECTOR PYTHON REFERENCE TESTS")
    print("========================================")
    
    # 1. Levenshtein algorithm matrix tests
    assert levenshtein_distance("paypa1", "paypal") == 1, "paypa1 -> paypal must be 1"
    assert levenshtein_distance("g00gle", "google") == 2, "g00gle -> google must be 2"
    assert levenshtein_distance("apple", "apple") == 0, "identical words must be 0"
    assert levenshtein_distance("micros0ft", "microsoft") == 1, "micros0ft -> microsoft must be 1"
    print("[PASS] Levenshtein DP Matrix calculation")

    # 2. Legitimate URL
    res = inspect_url("https://www.google.com")
    assert res['verdict'] == 'LOW RISK', f"Expected LOW RISK, got {res['verdict']}"
    assert res['score'] == 0, f"Expected score 0, got {res['score']}"
    print(f"[PASS] https://www.google.com -> {res['verdict']} (Score: {res['score']})")

    # 3. Typosquat on risky TLD
    res = inspect_url("http://paypa1-security.tk/login/verify")
    # Typosquat (+28), Risky TLD (+12), Multiple Keywords (+14), No HTTPS (+10), Multiple hyphens (+10) -> score capped at 100
    assert res['verdict'] == 'HIGH RISK', f"Expected HIGH RISK, got {res['verdict']}"
    assert res['score'] >= 50, f"Expected >= 50, got {res['score']}"
    print(f"[PASS] http://paypa1-security.tk/login/verify -> {res['verdict']} (Score: {res['score']})")

    # 4. Raw IP
    res = inspect_url("http://192.168.1.1/login")
    assert any(f[0] == 'Raw IP Host' for f in res['findings']), "Must flag raw IP host"
    assert any(f[0] == 'No HTTPS' for f in res['findings']), "Must flag no HTTPS"
    assert res['verdict'] in ('SUSPICIOUS', 'HIGH RISK')
    print(f"[PASS] http://192.168.1.1/login -> {res['verdict']} (Score: {res['score']})")

    # 5. @ Symbol obfuscation
    res = inspect_url("https://secure.bank.com@malicious-target.com/portal")
    assert any('@ Symbol Present' in f[0] for f in res['findings']), "Must flag @ symbol"
    print(f"[PASS] @ symbol URL -> Flagged: {res['findings']}")

    # 6. Punycode
    res = inspect_url("https://xn--pple-43d.com")
    assert any('Punycode Host' in f[0] for f in res['findings']), "Must flag punycode"
    print(f"[PASS] Punycode URL -> Flagged: {res['findings']}")

    # 7. Shortener
    res = inspect_url("https://bit.ly/3xY9ZwQ")
    assert any('URL Shortener' in f[0] for f in res['findings']), "Must flag shortener"
    print(f"[PASS] Shortener -> Flagged: {res['findings']}")

    # 8. Score capping test (> 100)
    res = inspect_url("http://192.168.1.1@paypa1-secure-portal.tk/login/verify/account/password?$!%*")
    assert res['score'] == 100, f"Score should cap at 100, got {res['score']}"
    print(f"[PASS] Score capping test: raw score {res['raw_score']} capped to {res['score']}")

    print("\nALL PYTHON REFERENCE VERIFICATION TESTS PASSED SUCCESSFULLY!\n")

if __name__ == '__main__':
    run_tests()
